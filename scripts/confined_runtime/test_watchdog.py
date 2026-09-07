import json
import unittest
from unittest.mock import patch

from . import watchdog

NAME = 'archon-confined-11111111-1111-4111-8111-111111111111'
IMAGE = 'sha256:' + 'a' * 64
IDENTITY = 'b' * 64


class WatchdogTests(unittest.TestCase):
    def test_transient_failures_and_timeouts_retain_cleanup_owner(self):
        with patch.object(watchdog.os, 'write'), patch.object(watchdog.time, 'monotonic', side_effect=[0, 2]), \
                patch.object(watchdog.time, 'sleep') as sleep, \
                patch.object(watchdog, 'remove_owned', side_effect=[False, TimeoutError(), OSError(), True]) as remove:
            self.assertEqual(watchdog.guard(NAME, 1, IMAGE), 0)
            self.assertEqual(remove.call_count, 4)
            self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 2, 4])

    def test_delete_uses_inspected_id_and_checks_complete_ownership(self):
        container = {'Id': IDENTITY, 'Name': '/' + NAME, 'Image': IMAGE,
                     'Config': {'Labels': {watchdog.OWNER_LABEL: NAME}}}
        with patch.object(watchdog, 'request', side_effect=[(200, json.dumps(container).encode()), (204, b'')]) as request:
            self.assertTrue(watchdog.remove_owned(NAME, IMAGE))
            self.assertEqual(request.call_args.args, ('DELETE', '/containers/' + IDENTITY + '?force=1&v=0'))
        for key, value in [('Id', 'bad'), ('Name', '/replacement'), ('Image', 'sha256:' + 'c' * 64), ('Config', {})]:
            with self.subTest(key=key), patch.object(watchdog, 'request', return_value=(200, json.dumps({**container, key: value}).encode())) as request:
                self.assertFalse(watchdog.remove_owned(NAME, IMAGE))
                self.assertEqual(request.call_count, 1)

    def test_only_confirmed_absence_releases_ownership(self):
        for status, absent in [(404, True), (500, False), (403, False)]:
            with self.subTest(status=status), patch.object(watchdog, 'request', return_value=(status, b'')):
                self.assertEqual(watchdog.remove_owned(NAME, IMAGE), absent)

    def test_total_deadline_ends_a_trickling_response(self):
        import socket
        import threading
        import time

        client, server = socket.socketpair()
        stopped = threading.Event()
        def drip():
            try:
                server.recv(4096)
                server.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n')
                while not stopped.wait(.01):
                    server.sendall(b'x')
            except OSError:
                pass
        connection = watchdog.DockerConnection()
        def connect():
            connection.sock = client
        thread = threading.Thread(target=drip)
        thread.start()
        try:
            started = time.monotonic()
            with patch.object(watchdog, 'DockerConnection', return_value=connection), \
                    patch.object(connection, 'connect', side_effect=connect), \
                    patch.object(watchdog, 'REQUEST_DEADLINE', .1):
                try:
                    status, content = watchdog.request('GET', '/containers/' + NAME + '/json')
                    self.assertEqual(status, 200)
                    self.assertLess(len(content), 1000)
                except (OSError, watchdog.http.client.HTTPException):
                    pass
            self.assertLess(time.monotonic() - started, 2)
        finally:
            stopped.set()
            server.close()
            client.close()
            thread.join(2)
