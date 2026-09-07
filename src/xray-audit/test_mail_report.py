"""Offline SMTP safety tests; never connect to a mail server or live database."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import smtplib
import sqlite3
import ssl
import sys
import tempfile
import types
import unittest
from unittest import mock


# The deployed entry point uses Linux flock. Windows tests only stub that import;
# these tests do not claim to exercise interprocess locking on Windows.
try:
    import fcntl  # noqa: F401
except ImportError:
    _fcntl = types.ModuleType("fcntl")
    _fcntl.LOCK_EX = 2
    _fcntl.flock = lambda *_args: None
    sys.modules.setdefault("fcntl", _fcntl)

_SPEC = importlib.util.spec_from_file_location(
    "audit_mail_report_test_target", Path(__file__).with_name("mail_report.py")
)
mail = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(mail)


class MailReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="audit-mail-offline-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.receipt = self.directory / "receipts" / "2026-09-06-a.json"
        self.settings = {
            "smtpEnable": "true",
            "smtpHost": "smtp.example.com",
            "smtpPort": "465",
            "smtpUsername": "sender@example.com",
            "smtpPassword": "OFFLINE_TEST_SECRET_NOT_FOR_LOGS",
            "smtpFrom": "sender@example.com",
            "smtpEncryptionType": "tls",
        }
        self.recipient = "audit@example.net"
        self.subject = "Node A daily report 2026-09-06"
        self.body = "Synthetic report. No employee or live server data."
        self.client = mock.Mock(name="offline_smtp_client")
        self.client.send_message.return_value = {}
        self.smtp_ssl = self.enterContext(mock.patch.object(
            mail.smtplib, "SMTP_SSL", return_value=self.client
        ))
        self.smtp = self.enterContext(mock.patch.object(
            mail.smtplib, "SMTP", return_value=self.client
        ))
        # A missed transport mock must fail immediately, never dial a server.
        self.enterContext(mock.patch.object(
            mail.socket, "create_connection",
            side_effect=AssertionError("Real network access is forbidden in tests"),
        ))
        self.output = io.StringIO()
        self.errors = io.StringIO()
        self.enterContext(contextlib.redirect_stdout(self.output))
        self.enterContext(contextlib.redirect_stderr(self.errors))

    def send(self, **overrides):
        arguments = {
            "settings": self.settings,
            "recipient": self.recipient,
            "subject": self.subject,
            "body": self.body,
            "receipt_path": self.receipt,
        }
        arguments.update(overrides)
        return mail.deliver(**arguments)

    def receipt_data(self):
        return json.loads(self.receipt.read_text(encoding="utf-8"))

    def assert_no_smtp(self):
        self.smtp.assert_not_called()
        self.smtp_ssl.assert_not_called()

    def test_3xui_tls_enum_uses_verified_implicit_tls(self):
        self.assertTrue(self.send())
        self.smtp.assert_not_called()
        self.smtp_ssl.assert_called_once()
        args, kwargs = self.smtp_ssl.call_args
        self.assertEqual(args, ("smtp.example.com", 465))
        self.assertEqual(kwargs["timeout"], 30)
        self.assertEqual(kwargs["context"].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(kwargs["context"].check_hostname)
        self.client.login.assert_called_once_with(
            self.settings["smtpUsername"], self.settings["smtpPassword"]
        )
        self.client.starttls.assert_not_called()
        self.assertEqual(self.receipt_data()["state"], "accepted_by_smtp")

    def test_starttls_is_required_before_authentication(self):
        self.settings.update(smtpPort="587", smtpEncryptionType="starttls")
        self.assertTrue(self.send())
        self.smtp_ssl.assert_not_called()
        self.smtp.assert_called_once_with("smtp.example.com", 587, timeout=30)
        names = [call[0] for call in self.client.mock_calls]
        self.assertEqual(names[:5], ["ehlo", "starttls", "ehlo", "login", "send_message"])
        context = self.client.starttls.call_args.kwargs["context"]
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

    def test_starttls_unavailable_never_falls_back_to_plaintext(self):
        self.settings.update(smtpPort="587", smtpEncryptionType="starttls")
        self.client.starttls.side_effect = smtplib.SMTPNotSupportedError("not supported")
        with self.assertRaises(RuntimeError):
            self.send()
        self.client.login.assert_not_called()
        self.client.send_message.assert_not_called()
        self.assertEqual(self.receipt_data()["state"], "not_sent")

    def test_tls_certificate_failure_never_sends_credentials(self):
        self.smtp_ssl.side_effect = ssl.SSLCertVerificationError("invalid certificate")
        with self.assertRaises(RuntimeError):
            self.send()
        self.client.login.assert_not_called()
        self.client.send_message.assert_not_called()
        self.assertEqual(self.receipt_data()["state"], "not_sent")

    def test_plaintext_and_unknown_transports_rejected(self):
        for encryption in ("none", "no", "plain", "", "opportunistic"):
            with self.subTest(encryption=encryption):
                self.settings["smtpEncryptionType"] = encryption
                with self.assertRaises(mail.MailNotReady):
                    self.send()
        self.assert_no_smtp()
        self.assertFalse(self.receipt.exists())

    def test_disabled_or_missing_smtp_is_fail_closed(self):
        for value in ({}, {"smtpEnable": "false"}, {"smtpEnable": "true"}):
            with self.subTest(settings=value):
                with self.assertRaises(mail.MailNotReady):
                    self.send(settings=value)
        for key in ("smtpHost", "smtpUsername", "smtpPassword"):
            with self.subTest(missing=key):
                value = dict(self.settings)
                value.pop(key)
                with self.assertRaises(mail.MailNotReady):
                    self.send(settings=value)
        self.assert_no_smtp()

    def test_invalid_ports_rejected_without_network(self):
        for port in ("0", "65536", "-1", "abc", "587\r\nAUTH"):
            with self.subTest(port=port):
                self.settings["smtpPort"] = port
                with self.assertRaises(mail.MailNotReady):
                    self.send()
        self.assert_no_smtp()

    def test_invalid_hosts_rejected_without_network(self):
        for host in (".example.com", "example.com/path", "example.com:465", "a\r\nb"):
            with self.subTest(host=host):
                self.settings["smtpHost"] = host
                with self.assertRaises(mail.MailNotReady):
                    self.send()
        self.assert_no_smtp()

    def test_addresses_reject_crlf_including_trailing_crlf(self):
        for value in (
            "audit@example.net\r\nBcc: attacker@example.org",
            "audit@example.net\r\n", "\naudit@example.net",
            "audit@example.net\r", "audit@example.net\n",
        ):
            with self.subTest(value=repr(value)):
                with self.assertRaises(mail.MailNotReady):
                    mail.address(value)

    def test_multiple_recipients_and_display_names_not_accepted(self):
        for value in (
            "audit@example.net,second@example.org", "Audit <audit@example.net>",
            "audit@example.net;second@example.org", "not-an-address",
        ):
            with self.subTest(value=value):
                with self.assertRaises(mail.MailNotReady):
                    self.send(recipient=value)
        self.assert_no_smtp()

    def test_subject_injection_rejected_before_network_or_receipt(self):
        for subject in ("Report\r\nBcc: attacker@example.org", "Report\n", "Report\r"):
            with self.subTest(subject=repr(subject)):
                with self.assertRaises(mail.MailNotReady):
                    self.send(subject=subject)
        self.assert_no_smtp()
        self.assertFalse(self.receipt.exists())

    def test_sender_injection_rejected_before_network(self):
        self.settings["smtpFrom"] = "sender@example.com\r\nBcc: attacker@example.org"
        with self.assertRaises(mail.MailNotReady):
            self.send()
        self.assert_no_smtp()

    def test_message_body_is_content_not_headers(self):
        body = "Bcc: attacker@example.org\n\nSynthetic daily report"
        self.assertTrue(self.send(body=body))
        message = self.client.send_message.call_args.args[0]
        self.assertIsNone(message["Bcc"])
        self.assertEqual(message["To"], self.recipient)
        self.assertEqual(message["From"], self.settings["smtpFrom"])
        self.assertIn(body, message.get_content())

    def test_success_receipt_prevents_second_send(self):
        self.assertTrue(self.send())
        first = self.receipt_data()
        self.assertTrue(self.send())
        self.assertEqual(self.receipt_data(), first)
        self.client.send_message.assert_called_once()
        self.smtp_ssl.assert_called_once()

    def test_sending_and_uncertain_receipts_fail_closed(self):
        for state in ("sending", "uncertain"):
            with self.subTest(state=state):
                mail.atomic_json(self.receipt, {"state": state})
                self.assertFalse(self.send())
        self.assert_no_smtp()

    def test_corrupt_receipt_does_not_allow_another_send(self):
        self.receipt.parent.mkdir(parents=True)
        self.receipt.write_text("not valid JSON", encoding="utf-8")
        with self.assertRaises((ValueError, RuntimeError, mail.MailNotReady)):
            self.send()
        self.assert_no_smtp()

    def test_sending_receipt_is_persisted_before_smtp_submission(self):
        def observe_receipt(_message):
            self.assertEqual(self.receipt_data()["state"], "sending")
            return {}

        self.client.send_message.side_effect = observe_receipt
        self.assertTrue(self.send())

    def test_no_submission_when_initial_receipt_cannot_be_persisted(self):
        with mock.patch.object(mail, "atomic_json", side_effect=OSError("disk full")):
            with self.assertRaises((OSError, RuntimeError)):
                self.send()
        self.client.send_message.assert_not_called()

    def test_uncertain_submission_is_not_automatically_retried(self):
        self.client.send_message.side_effect = smtplib.SMTPServerDisconnected(
            "connection lost after DATA"
        )
        with self.assertRaises(RuntimeError):
            self.send()
        self.assertEqual(self.receipt_data()["state"], "uncertain")
        self.client.send_message.side_effect = None
        self.assertFalse(self.send())
        self.client.send_message.assert_called_once()

    def test_failed_success_receipt_leaves_no_automatic_resend_path(self):
        real_atomic = mail.atomic_json
        calls = 0

        def fail_after_initial_receipt(path, data):
            nonlocal calls
            calls += 1
            if calls > 1:
                raise OSError("disk full after SMTP accepted")
            real_atomic(path, data)

        with mock.patch.object(mail, "atomic_json", side_effect=fail_after_initial_receipt):
            with self.assertRaises((OSError, RuntimeError)):
                self.send()
        self.assertEqual(self.receipt_data()["state"], "sending")
        self.assertFalse(self.send())
        self.client.send_message.assert_called_once()

    def test_failed_auth_is_not_sent_and_safe_to_retry(self):
        self.client.login.side_effect = smtplib.SMTPAuthenticationError(535, b"bad credentials")
        with self.assertRaises(RuntimeError):
            self.send()
        self.assertEqual(self.receipt_data()["state"], "not_sent")
        self.client.send_message.assert_not_called()
        self.client.login.side_effect = None
        self.assertTrue(self.send())
        self.client.send_message.assert_called_once()

    def test_error_output_and_receipt_do_not_disclose_password(self):
        secret = self.settings["smtpPassword"]
        self.client.login.side_effect = RuntimeError("authentication failed: " + secret)
        with self.assertRaises(RuntimeError) as captured:
            self.send()
        visible = (
            str(captured.exception) + self.output.getvalue() + self.errors.getvalue()
            + self.receipt.read_text(encoding="utf-8")
        )
        self.assertNotIn(secret, visible)

    def test_refused_recipient_is_never_marked_accepted(self):
        self.client.send_message.return_value = {self.recipient: (550, b"rejected")}
        with self.assertRaises(RuntimeError):
            self.send()
        self.assertNotEqual(self.receipt_data()["state"], "accepted_by_smtp")

    def test_read_settings_uses_only_temporary_database_and_expected_keys(self):
        database = self.directory / "synthetic-settings.sqlite"
        with contextlib.closing(sqlite3.connect(database)) as connection:
            with connection:
                connection.execute("CREATE TABLE settings (key TEXT, value TEXT)")
                connection.executemany(
                    "INSERT INTO settings VALUES (?,?)",
                    [*self.settings.items(), ("panelSecret", "not-selected"),
                     ("smtpTo", "unrelated-recipient@example.org")],
                )
        self.assertEqual(mail.read_settings(database), self.settings)
        self.assert_no_smtp()

    def test_missing_database_is_not_created(self):
        database = self.directory / "missing.sqlite"
        with self.assertRaises(sqlite3.OperationalError):
            mail.read_settings(database)
        self.assertFalse(database.exists())

    def test_check_config_prints_no_password_and_sends_nothing(self):
        with mock.patch.object(mail, "read_settings", return_value=self.settings), mock.patch.object(
            sys, "argv", ["mail_report.py", "--recipient", self.recipient, "--check-config"]
        ):
            self.assertEqual(mail.main(), 0)
        result = json.loads(self.output.getvalue())
        self.assertTrue(result["ready"])
        self.assertNotIn(self.settings["smtpPassword"], self.output.getvalue())
        self.assert_no_smtp()

    def test_unconfigured_cli_reports_pending_without_smtp(self):
        with mock.patch.object(mail, "read_settings", return_value={}), mock.patch.object(
            sys, "argv", ["mail_report.py", "--recipient", self.recipient, "--check-config"]
        ):
            self.assertEqual(mail.main(), 78)
        self.assertIn("SMTP_PENDING", self.errors.getvalue())
        self.assert_no_smtp()


if __name__ == "__main__":
    unittest.main(verbosity=2)
