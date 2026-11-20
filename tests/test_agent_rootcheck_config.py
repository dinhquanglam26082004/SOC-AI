import pytest

from scripts.enable_agent_rootcheck import merge_rootcheck


def test_merges_only_the_named_agent_and_preserves_its_sources():
    old = ('<agent_config name="^ubuntu-agent$"><localfile><location>dns.log</location>'
           '</localfile></agent_config><agent_config name="other"><rootcheck>'
           '<disabled>yes</disabled></rootcheck></agent_config>')
    new = merge_rootcheck(old)
    assert '<rootcheck><disabled>no</disabled></rootcheck>' in new
    assert '<localfile><location>dns.log</location></localfile>' in new
    assert '<agent_config name="other"><rootcheck><disabled>yes</disabled></rootcheck></agent_config>' in new
    assert merge_rootcheck(new) == new


def test_only_changes_disabled_inside_an_existing_rootcheck():
    old = ('<agent_config name="^ubuntu-agent$"><rootcheck><disabled>yes</disabled>'
           '<frequency>3600</frequency></rootcheck></agent_config>')
    assert merge_rootcheck(old) == old.replace('<disabled>yes</disabled>', '<disabled>no</disabled>')


def test_ambiguous_target_is_not_modified():
    with pytest.raises(ValueError, match='exactly one'):
        merge_rootcheck('<agent_config name="other"></agent_config>')
    with pytest.raises(ValueError, match='Multiple rootcheck'):
        merge_rootcheck('<agent_config name="^ubuntu-agent$"><rootcheck></rootcheck><rootcheck></rootcheck></agent_config>')
    with pytest.raises(ValueError, match='Unsupported rootcheck'):
        merge_rootcheck('<agent_config name="^ubuntu-agent$"><rootcheck /></agent_config>')
