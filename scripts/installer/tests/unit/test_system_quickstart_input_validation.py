import importlib.util
import os
import sys
import types
import unittest
from unittest.mock import MagicMock

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
QUICKSTART_PATH = os.path.join(
    PROJECT_ROOT, "malcolm-iso", "config", "includes.chroot", "usr", "local", "bin", "system-quickstart.py"
)


def _load_quickstart():
    # system-quickstart.py imports python3-dialog and instantiates a Dialog at import
    # time; stub that out so the validation helpers can be exercised headlessly
    fake_dialog = types.ModuleType("dialog")
    fake_dialog.Dialog = MagicMock()
    sys.modules.setdefault("dialog", fake_dialog)
    scripts_dir = os.path.join(PROJECT_ROOT, "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    spec = importlib.util.spec_from_file_location("system_quickstart", QUICKSTART_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestSystemQuickstartInputValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qs = _load_quickstart()

    def test_valid_hostnames_accepted(self):
        for value in ("malcolm", "sensor-01", "hedgehog.example.com", "a1.b2.c3", "10.0.0.5", "fe80::1"):
            self.assertTrue(self.qs.is_valid_hostname(value), value)

    def test_hostname_shell_injection_rejected(self):
        for value in (
            "",
            "x;cp /bin/bash /tmp/r;chmod 4755 /tmp/r",
            "host $(id)",
            "host`id`",
            "host|id",
            "host name",
            "-leading",
            "trailing-",
            "under_score",
            "a" * 64,
            "host\nname",
        ):
            self.assertFalse(self.qs.is_valid_hostname(value), repr(value))

    def test_valid_time_sync_urls_accepted(self):
        for value in (
            self.qs.TIME_SYNC_HTPDATE_DEFAULT_URL,
            "https://time.example.com",
            "http://10.1.2.3:8080",
            "https://[fe80::1]:443",
            "https://malcolm.local:443/",
        ):
            self.assertEqual(self.qs.validate_time_sync_url(value), value)

    def test_time_sync_url_shell_injection_rejected(self):
        for value in (
            "",
            "https://1.1.1.1:443;id>/root/pwn",
            "https://1.1.1.1:443 && touch /root/pwn",
            "https://1.1.1.1:443$(id)",
            "https://1.1.1.1:443`id`",
            "https://1.1.1.1:443|id",
            "https://1.1.1.1:443\nid",
            "https://1.1.1.1:443?x=1",
            "https://1.1.1.1:443#frag",
            "https://user:pass@1.1.1.1:443",
            "ftp://1.1.1.1",
            "file:///etc/shadow",
            "1.1.1.1:443",
            "https://",
            "https://1.1.1.1:99999",
            "https://bad host:443",
        ):
            self.assertIsNone(self.qs.validate_time_sync_url(value), repr(value))

    def test_cron_entry_quotes_url(self):
        line = self.qs.htpdate_cron_entry(15, "https://1.1.1.1:443")
        self.assertEqual(line, "*/15 * * * * root /usr/sbin/htpdate -4 -a -l https://1.1.1.1:443\n")
        hostile = "https://1.1.1.1:443;id>/root/pwn"
        line = self.qs.htpdate_cron_entry(5, hostile)
        self.assertTrue(line.startswith("*/5 * * * * root /usr/sbin/htpdate -4 -a -l '"))
        self.assertIn("'https://1.1.1.1:443;id>/root/pwn'", line)

    def test_cron_entry_roundtrips_through_parser(self):
        import tempfile

        for url in ("https://time.example.com:8443", "https://[fe80::1]:443"):
            with tempfile.NamedTemporaryFile("w", suffix=".cron", delete=False) as f:
                f.write("SHELL=/bin/bash\n\n")
                f.write(self.qs.htpdate_cron_entry(20, url))
                cron_path = f.name
            try:
                orig = self.qs.TIME_SYNC_HTPDATE_CRON
                self.qs.TIME_SYNC_HTPDATE_CRON = cron_path
                self.assertEqual(self.qs.get_htpdate_config(), (url, 20))
            finally:
                self.qs.TIME_SYNC_HTPDATE_CRON = orig
                os.unlink(cron_path)


class TestRunSubprocessArgv(unittest.TestCase):
    def test_list_command_is_not_shell_interpreted(self):
        from scripts.malcolm_utils import run_subprocess

        hostile = "a;echo INJECTED"
        retcode, output = run_subprocess(["echo", hostile])
        self.assertEqual(retcode, 0)
        self.assertEqual(output, [hostile])

    def test_string_command_still_uses_shell(self):
        from scripts.malcolm_utils import run_subprocess

        retcode, output = run_subprocess("echo one; echo two")
        self.assertEqual(retcode, 0)
        self.assertEqual(output, ["one", "two"])


if __name__ == "__main__":
    unittest.main()
