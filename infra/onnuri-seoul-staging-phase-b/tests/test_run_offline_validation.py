import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location("runner", HERE / "run_offline_validation.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class OfflineRunnerTests(unittest.TestCase):
    def test_rejects_cloud_and_proxy_environment_names(self):
        errors = runner.inherited_environment_errors({"GOOGLE_APPLICATION_CREDENTIALS": "x", "HTTPS_PROXY": "x", "safe": "x"})
        self.assertEqual(["GOOGLE_APPLICATION_CREDENTIALS", "HTTPS_PROXY"], errors)

    def test_all_terraform_commands_are_allowlisted(self):
        self.assertEqual(("version",), runner.TERRAFORM_COMMANDS[0])
        self.assertEqual(("test",), runner.TERRAFORM_COMMANDS[-1])
        forbidden = {"plan", "apply", "destroy", "show", "state"}
        self.assertFalse(forbidden.intersection({part for command in runner.TERRAFORM_COMMANDS for part in command}))

    def test_scrubbed_environment_has_only_allowlisted_keys(self):
        environment = runner.scrubbed_environment("/tmp/config", "/tmp/data", "/tmp/home")
        self.assertEqual({"PATH", "HOME", "TMPDIR", "LC_ALL", "TZ", "CHECKPOINT_DISABLE", "TF_CLI_CONFIG_FILE", "TF_DATA_DIR"}, set(environment))
        self.assertEqual("C", environment["LC_ALL"])
        self.assertEqual("UTC", environment["TZ"])

    def test_classifies_only_exact_sandbox_provider_ipc_failure(self):
        output = (
            "Failed to load plugin schemas\n"
            "failed to instantiate provider\n"
            "Failed to read any lines from plugin's stdout"
        )
        self.assertTrue(runner.sandbox_provider_ipc_blocked(("validate",), output))
        self.assertFalse(runner.sandbox_provider_ipc_blocked(("fmt", "-check", "-recursive"), output))
        self.assertFalse(runner.sandbox_provider_ipc_blocked(("validate",), "Invalid Terraform configuration"))


if __name__ == "__main__":
    unittest.main()
