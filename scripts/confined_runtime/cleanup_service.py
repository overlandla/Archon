"""Independent durable cleanup ownership; never transitions admission state.

The unit survives admission-service termination. Journal facts retain the exact
container name, image and deadline before creation. Each pass revisits expired
facts, even after absence, because a timed-out daemon create may finish late.
"""
import math
import os
import re
import signal
import socket
import threading
import time

from .https_transport import parse_json
from .watchdog import remove_owned


def sweep(journal, *, after=0, now=None, remove=remove_owned):
    now = time.time() if now is None else now
    with journal.connect() as connection:
        rows = connection.execute(
            "SELECT rowid, value FROM confined_run_facts WHERE name='container' AND rowid>? ORDER BY rowid LIMIT 32",
            (after,)).fetchall()
    healthy = True
    for row in rows:
        try:
            owner = parse_json(row['value'])
            if (not isinstance(owner, dict) or set(owner) != {'name', 'image', 'expires_at'}
                    or not isinstance(owner['name'], str)
                    or not re.fullmatch(r'archon-confined-[0-9a-f-]{36}', owner['name'])
                    or not isinstance(owner['image'], str)
                    or not re.fullmatch(r'sha256:[0-9a-f]{64}', owner['image'])
                    or type(owner['expires_at']) not in (int, float) or not math.isfinite(owner['expires_at'])):
                raise ValueError('invalid_cleanup_owner')
            if owner['expires_at'] <= now and not remove(owner['name'], owner['image']):
                healthy = False
        except Exception:
            healthy = False
    return (rows[-1]['rowid'] if len(rows) == 32 else 0), healthy


def ready():
    address = os.environ.get('NOTIFY_SOCKET')
    if address is None:
        raise RuntimeError('cleanup_requires_supervision')
    if address.startswith('@'):
        address = '\0' + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as stream:
        stream.connect(address)
        stream.sendall(b'READY=1')


def serve(journal):
    stopped = threading.Event()
    def stop(_signum, _frame):
        stopped.set()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    after = 0
    announced, pass_healthy = False, True
    while not stopped.is_set():
        try:
            after, healthy = sweep(journal, after=after)
        except Exception:
            after, healthy = 0, False
        pass_healthy = pass_healthy and healthy
        if after == 0:
            if pass_healthy and not announced:
                ready()
                announced = True
            pass_healthy = True
        if not healthy:
            # A fixed diagnostic preserves uncertainty without exporting run data.
            print('confined_cleanup_pending', flush=True)
        stopped.wait(1 if after else 5)
