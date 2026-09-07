import unittest
from unittest.mock import patch

from .https_transport import HTTPS, Origin, parse_json


class TransportTests(unittest.TestCase):
    def test_unknown_routes_and_exhausted_budget_do_not_open_connection(self):
        transport = HTTPS(Origin("api.github.com", "synthetic-credential"), frozenset({("POST", "/allowed")}), request_limit=1)
        with patch("http.client.HTTPSConnection") as connect:
            for method, path in (("POST", "https://evil.invalid/allowed"), ("DELETE", "/allowed"), ("POST", "//evil.invalid")):
                with self.assertRaises(ValueError):
                    transport(method, path, {})
            transport.remaining = 0
            with self.assertRaises(RuntimeError):
                transport("POST", "/allowed", {})
            connect.assert_not_called()
        self.assertNotIn("synthetic-credential", repr(transport.origin))

    def test_redirect_and_lost_ack_never_retry_or_forward_credential(self):
        transport = HTTPS(Origin("api.github.com", "synthetic-credential"), frozenset({("POST", "/allowed")}))
        with patch("http.client.HTTPSConnection") as connect:
            connection = connect.return_value
            connection.getresponse.return_value.status = 302
            with self.assertRaises(RuntimeError):
                transport("POST", "/allowed", {})
            self.assertEqual(connect.call_count, 1)
            self.assertEqual(connect.call_args.args, ("api.github.com", 443))
            connection.close.assert_called_once()
            connection.getresponse.side_effect = ConnectionError("lost acknowledgement")
            with self.assertRaises(ConnectionError):
                transport("POST", "/allowed", {})
            self.assertEqual(connect.call_count, 2)

    def test_ambiguous_json_and_oversized_response_are_rejected(self):
        for data in (b'{"id":1,"id":2}', b'{"id":NaN}'):
            with self.assertRaises(ValueError):
                parse_json(data)
        transport = HTTPS(Origin("api.github.com", "synthetic-credential"), frozenset({("GET", "/allowed")}))
        with patch("http.client.HTTPSConnection") as connect:
            response = connect.return_value.getresponse.return_value
            response.status = 200
            response.read1.return_value = b"x" * 65536
            with self.assertRaises(RuntimeError):
                transport("GET", "/allowed", None)
            self.assertEqual(response.read1.call_count, 33)
