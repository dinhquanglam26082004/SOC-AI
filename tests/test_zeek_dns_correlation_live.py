"""Opt-in integration checks against a running Wazuh with the project rules.

Set SOC_WAZUH_LOGTEST_CONTAINER to an isolated test manager. wazuh-logtest
does not inject events into the live alert stream or create SOC alerts.
"""

import json
import os
import re
import subprocess

import pytest


CONTAINER = os.getenv('SOC_WAZUH_LOGTEST_CONTAINER')
pytestmark = pytest.mark.skipif(not CONTAINER, reason='Requires a test Wazuh manager')


def event(query, *, source='192.0.2.10', destination='192.0.2.53', port=53,
          qtype='NULL', **extra):
    return {'ts': 1794996980.9, 'uid': 'Ctest', 'id.orig_h': source,
            'id.resp_h': destination, 'id.resp_p': port, 'proto': 'udp',
            'query': query + '.test.invalid', 'qtype_name': qtype, **extra}


def matched_rules(events):
    result = subprocess.run(
        ['docker', 'exec', '-i', CONTAINER, '/var/ossec/bin/wazuh-logtest',
         '-l', '/opt/zeek/logs/current/dns.log'],
        input=''.join(json.dumps(item) + '\n' for item in events),
        capture_output=True, text=True, timeout=45, check=True,
    )
    output = (result.stdout + '\n' + result.stderr).replace('\r', '')
    ids = re.findall(r"^\s*id: '(\d+)'\s*$", output, flags=re.MULTILINE)
    assert len(ids) == len(events), output
    return ids


def test_rare_query_requires_a_related_burst():
    assert matched_rules([event('one')]) == ['100183']
    assert matched_rules([event(str(i)) for i in range(5)]) == ['100183'] * 4 + ['100181']
    assert matched_rules([event('same') for _ in range(6)]) == ['100183'] * 6
    # The last observation differs from previous ones, but only two names
    # occur. Wazuh different_field does not mean five distinct query names.
    assert matched_rules([event('a')] * 4 + [event('b')]) == ['100183'] * 4 + ['100181']


@pytest.mark.parametrize('variation', ['source', 'destination', 'port', 'qtype'])
def test_unrelated_scopes_do_not_share_a_counter(variation):
    samples = []
    for i in range(5):
        options = {
            'source': f'192.0.2.{10 + i}' if variation == 'source' else '192.0.2.10',
            'destination': f'192.0.2.{53 + i}' if variation == 'destination' else '192.0.2.53',
            'port': 53 + i if variation == 'port' else 53,
            'qtype': ['NULL', 'KEY', 'PRIVATE', 'NULL', 'KEY'][i] if variation == 'qtype' else 'NULL',
        }
        samples.append(event(str(i), **options))
    assert matched_rules(samples) == ['100183'] * 5


def test_separate_sources_each_trigger_and_nxdomain_is_not_lost():
    # logtest checks correlation; it does not establish production ignore scope.
    events = [event(str(i), source='192.0.2.10', rcode_name='NXDOMAIN') for i in range(5)]
    events += [event(str(i), source='192.0.2.11', rcode_name='NXDOMAIN') for i in range(5)]
    assert matched_rules(events) == (['100183'] * 4 + ['100181']) * 2


def test_long_null_query_still_reaches_existing_tunneling_rule():
    events = [event('z8' * 16 + str(i)) for i in range(6)]
    assert matched_rules(events) == ['100154', '100154', '100154', '100154', '100156', '100154']


def test_escaped_dns_bytes_count_as_one_label_octet():
    # Zeek represents non-ASCII octets as literal \xNN sequences. A 31-octet
    # label remains below the threshold despite its longer display text.
    short = ('z' * 15) + (r'\xf9' * 16)
    assert matched_rules([event(short)]) == ['100183']

    # Keep samples in a single logtest session to exercise correlation.
    long_labels = [('z' * 15) + (r'\xf9' * 16) + str(i) for i in range(5)]
    assert matched_rules([event(label) for label in long_labels]) == [
        '100154', '100154', '100154', '100154', '100156'
    ]


def test_escaped_octets_do_not_bypass_long_label_domain_exclusions():
    sample = event(('z' * 16) + (r'\xf9' * 16))
    sample['query'] = ('z' * 16) + (r'\xf9' * 16) + '.cloudfront.net'
    assert matched_rules([sample]) == ['100183']
