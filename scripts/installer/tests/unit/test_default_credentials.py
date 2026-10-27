#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests ensuring well-known default credentials are neither shipped in the
direnv/just convenience configuration nor accepted by noninteractive auth_setup.

Regression tests for the finding that .envrc.example shipped working admin/Arkime/Keycloak
credentials (maltest / M@lc0lm / Malcolm) which `just auth-setup` provisioned verbatim.
"""

import os
import re
import shutil
import subprocess
import unittest

from scripts.malcolm_utils import (
    KNOWN_DEFAULT_PASSWORDS,
    is_known_default_password,
    is_known_default_password_hash,
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
AUTH_PASSWORD_VARS = (
    "AUTH_ADMIN_PASSWORD",
    "AUTH_ARKIME_PASSWORD",
    "AUTH_KEYCLOAK_BOOTSTRAP_PASSWORD",
    "AUTH_KEYCLOAK_CLIENT_SECRET",
)

try:
    import bcrypt
except ImportError:
    bcrypt = None


def _read(relpath):
    with open(os.path.join(PROJECT_ROOT, relpath), "r") as f:
        return f.read()


def _exports(text):
    return dict(re.findall(r"^export\s+([A-Z0-9_]+)=(.*)$", text, flags=re.MULTILINE))


class TestKnownDefaultPassword(unittest.TestCase):
    def test_shipped_defaults_are_known(self):
        for value in ("M@lc0lm", "Malcolm", "maltest", "changeme", "CHANGEME_ADMIN_PASSWORD", "", "   ", None):
            self.assertTrue(is_known_default_password(value), value)

    def test_unique_password_is_not_known(self):
        self.assertFalse(is_known_default_password("c0rrect-h0rse-battery-staple-7f3a"))

    def test_known_default_set_contains_previously_shipped_values(self):
        self.assertTrue({"M@lc0lm", "Malcolm"}.issubset(KNOWN_DEFAULT_PASSWORDS))


@unittest.skipUnless(shutil.which("openssl"), "openssl not available")
class TestKnownDefaultPasswordHashOpenssl(unittest.TestCase):
    @staticmethod
    def _openssl_hash(password, algo="6"):
        return subprocess.run(
            ["openssl", "passwd", f"-{algo}", "-stdin"],
            input=password,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

    def test_sha512_hash_of_default_is_detected(self):
        self.assertTrue(is_known_default_password_hash(self._openssl_hash("M@lc0lm")))

    def test_md5crypt_hash_of_default_is_detected(self):
        self.assertTrue(is_known_default_password_hash(self._openssl_hash("Malcolm", "1")))

    def test_hash_of_unique_password_is_not_detected(self):
        self.assertFalse(is_known_default_password_hash(self._openssl_hash("c0rrect-h0rse-battery-staple-7f3a")))

    def test_garbage_is_not_detected(self):
        self.assertFalse(is_known_default_password_hash(""))
        self.assertFalse(is_known_default_password_hash("not-a-hash"))


@unittest.skipUnless(bcrypt, "bcrypt module not available")
class TestKnownDefaultPasswordHashBcrypt(unittest.TestCase):
    def test_bcrypt_hash_of_default_is_detected(self):
        hashed = bcrypt.hashpw(b"M@lc0lm", bcrypt.gensalt(rounds=5)).decode()
        self.assertTrue(is_known_default_password_hash(hashed))

    def test_bcrypt_hash_of_empty_password_is_detected(self):
        hashed = bcrypt.hashpw(b"", bcrypt.gensalt(rounds=5)).decode()
        self.assertTrue(is_known_default_password_hash(hashed))

    def test_bcrypt_hash_of_unique_password_is_not_detected(self):
        hashed = bcrypt.hashpw(b"c0rrect-h0rse-battery-staple-7f3a", bcrypt.gensalt(rounds=5)).decode()
        self.assertFalse(is_known_default_password_hash(hashed))


class TestConvenienceConfigShipsNoCredentials(unittest.TestCase):
    def test_envrc_example_has_no_working_passwords(self):
        exports = _exports(_read(".envrc.example"))
        for var in AUTH_PASSWORD_VARS:
            self.assertIn(var, exports)
            self.assertEqual(exports[var].strip().strip("\"'"), "", f"{var} must be blank in .envrc.example")

    def test_envrc_example_has_no_default_admin_username(self):
        exports = _exports(_read(".envrc.example"))
        self.assertEqual(exports["AUTH_ADMIN_USERNAME"].strip(), "")

    def test_envrc_example_contains_no_known_default_password_literal(self):
        text = _read(".envrc.example")
        for value in ("M@lc0lm", "maltest"):
            self.assertNotIn(value, text)

    def test_justfile_has_no_default_password_fallbacks(self):
        text = _read(".justfile")
        for match in re.findall(r"\$\{AUTH_[A-Z_]*PASSWORD[A-Z_]*:-([^}]*)\}", text):
            self.assertFalse(is_known_default_password(match), f"fallback '{match}' is a known default")
        self.assertNotIn("${AUTH_ARKIME_PASSWORD:-Malcolm}", text)

    def test_justfile_auth_setup_requires_admin_credentials(self):
        text = _read(".justfile")
        start = text.index("\nauth-setup:")
        recipe = text[start : text.index("./scripts/auth_setup", start)]
        self.assertIn('-z "${AUTH_ADMIN_PASSWORD}"', recipe)
        self.assertIn('-z "${AUTH_ADMIN_USERNAME}"', recipe)

    def test_auth_setup_has_no_default_arkime_secret(self):
        text = _read(os.path.join("scripts", "auth_setup"))
        arg = text[text.index("'--auth-arkime-password'") :]
        arg = arg[: arg.index("help=")]
        self.assertIn("default=''", arg)


if __name__ == "__main__":
    unittest.main()
