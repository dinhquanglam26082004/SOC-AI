"""Small isolated tests for patch policy; does not require the entire SOC-AI repo."""
import ast
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import sys
import types
import unittest

patch_path = Path(__file__).with_name('apply_socai_tool_optimization.py')
spec = importlib.util.spec_from_file_location('patch_module', patch_path)
patch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch)


def stamp(value):
    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    return dt.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')

# Fake just the one dependency of the new helper.
common = types.ModuleType('common')
log_index = types.ModuleType('common.log_index')
log_index.utc_stamp = stamp
sys.modules['common'] = common
sys.modules['common.log_index'] = log_index
module = types.ModuleType('tool_call_policy')
exec(compile(patch.HELPER, 'tool_call_policy.py', 'exec'), module.__dict__)


class FakeModel:
    @classmethod
    def model_validate(cls, arguments):
        if not isinstance(arguments, dict) or any(k not in {'agent_id', 'since', 'until', 'ip', 'limit', 'file_path'} for k in arguments):
            raise ValueError('invalid')
        class Result:
            def model_dump(self):
                return {**{'agent_id': None, 'since': None, 'until': None, 'ip': None, 'limit': 20, 'file_path': None}, **arguments}
        return Result()


class TestToolCalls(unittest.TestCase):
    models = {'search_file_changes': FakeModel}
    env = {'agent': '001', 'since': '2026-11-20T10:00:00Z', 'until': '2026-11-20T10:30:00Z'}

    def normalize(self, args):
        return module.normalized_tool_args('search_file_changes', args, self.models, **self.env)

    def test_defaults_equivalent_to_explicit_values(self):
        a = self.normalize({})
        b = self.normalize({'agent_id': '001', 'since': '2026-11-20T10:00:00+00:00',
                            'until': '2026-11-20T10:30:00Z', 'limit': 20})
        self.assertEqual(a, b)

    def test_different_filter_distinct(self):
        self.assertNotEqual(self.normalize({}), self.normalize({'file_path': '/etc/passwd'}))

    def test_foreign_agent_preserved_for_validation(self):
        self.assertEqual(self.normalize({'agent_id': '999'})['agent_id'], '999')

    def test_invalid_argument_kept_for_rejection(self):
        bad = {'extraneous': True}
        self.assertEqual(self.normalize(bad), bad)

    def test_helper_compiles(self):
        ast.parse(patch.HELPER)

    def test_available_tools_are_restricted_after_success(self):
        # Extract the pure availability helpers from the guarded patch.
        tree = ast.parse(Path(patch_path).read_text(encoding='utf-8'))
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'patched_graph')
        snippet = None
        for node in fn.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'new':
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and 'COMPLETED_TOOL_STATUSES' in node.value.value:
                    snippet = node.value.value
                    break
        self.assertIsNotNone(snippet)
        ns = {'MODELS': {'search_rootkit_evidence': None, 'get_event_details': None, 'search_runbook': None}}
        exec(snippet, ns)
        state = {'observations': [{'tool': 'search_rootkit_evidence', 'status': 'ok', 'truncated': False}]}
        self.assertNotIn('search_rootkit_evidence', ns['available_tool_names'](state))
        self.assertIn('get_event_details', ns['available_tool_names'](state))
        state['observations'][0]['truncated'] = True
        self.assertIn('search_rootkit_evidence', ns['available_tool_names'](state))
        state['observations'][0]['status'] = 'error'
        self.assertIn('search_rootkit_evidence', ns['available_tool_names'](state))

    def test_patch_contains_key_safety_checks(self):
        src = Path(patch_path).read_text(encoding='utf-8')
        for phrase in ('equivalent_query_already_completed', 'tool_query_limit',
                       'COMPLETED_TOOL_STATUSES', 'request_key', 'shutil.copy2',
                       'compile(updated, str(graph)', 'root.parent/'):
            self.assertIn(phrase, src)


if __name__ == '__main__':
    unittest.main(verbosity=2)
