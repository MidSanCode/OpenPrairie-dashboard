"""Bounds on the login form's input and on its throttle table (M-7).

The submitted username becomes part of a throttle key, and neither it nor the
password had a length limit; the throttle table also only ever shrank on a
*successful* login, and even a request that was being throttled added an entry.
A handful of oversized usernames could therefore grow it without bound on a panel
exposed through a reverse proxy.

Run in a subprocess, like test_secrets_and_subprocess.py: importing the panel's
config validates it and may write a secret key, and the suite should not inherit
that state.
"""

import json
import os
import secrets
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PROBE = r"""
import json
import re
import time

import app as panel

panel.app.config.update(TESTING=True)
out = {}

# The table must stay bounded no matter how many distinct keys arrive.
panel._login_attempts.clear()
for i in range(panel._LOGIN_MAX_TRACKED_KEYS + 25):
    panel._login_record_failure("10.0.0.1|user%d" % i)
out["bounded"] = len(panel._login_attempts) <= panel._LOGIN_MAX_TRACKED_KEYS
out["entries"] = len(panel._login_attempts)

# Asking whether a key is blocked must not create it.
panel._login_attempts.clear()
panel._login_blocked("203.0.113.9|never-seen")
out["blocked_does_not_insert"] = "203.0.113.9|never-seen" not in panel._login_attempts

# Trimming also drops entries whose stamps are older than the window.
panel._login_attempts.clear()
panel._login_attempts["10.0.0.1|old"] = [time.monotonic() - 7200]
for i in range(panel._LOGIN_MAX_TRACKED_KEYS + 5):
    panel._login_record_failure("10.0.0.2|u%d" % i)
out["expired_dropped"] = "10.0.0.1|old" not in panel._login_attempts

client = panel.app.test_client()
page = client.get("/login")
match = re.search(r'name="csrf_token"\s+value="([^"]+)"', page.get_data(as_text=True))
token = match.group(1) if match else ""
out["oversized_username"] = client.post(
    "/login", data={"username": "a" * 65, "password": "x", "csrf_token": token}
).status_code
out["oversized_password"] = client.post(
    "/login", data={"username": "admin", "password": "x" * 257, "csrf_token": token}
).status_code

# A normal-length attempt must get past the length check; it reaches the
# database, which this probe deliberately does not have.
try:
    status = client.post(
        "/login", data={"username": "admin", "password": "x" * 8, "csrf_token": token}
    ).status_code
    out["normal_lengths"] = status
except Exception:
    out["normal_lengths"] = "reached_db"
print(json.dumps(out))
"""


@pytest.fixture(scope="module")
def probe():
    env = dict(os.environ)
    env.update(
        {
            # Dummy connection details: nothing in the probe should reach the
            # database, and a real deployment's credentials must not be used.
            "ADMIN_DB_HOST": "127.0.0.1",
            "ADMIN_DB_PORT": "5432",
            "ADMIN_DB_USER": "pytest",
            "ADMIN_DB_PASSWORD": "pytest",
            "ADMIN_DB_NAME": "pytest",
            "ADMIN_SECRET_KEY": secrets.token_urlsafe(48),
            "RUSTFS_ACCESS_KEY": "pytest",
            "RUSTFS_SECRET_KEY": "pytest",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONPATH": REPO_ROOT + os.pathsep + env.get("PYTHONPATH", ""),
        }
    )
    proc = subprocess.run(
        [sys.executable, "-c", PROBE],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, f"probe failed:\n{proc.stdout}\n{proc.stderr}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_throttle_table_stays_bounded(probe):
    assert probe["bounded"] is True, probe
    assert probe["entries"] <= 4096


def test_checking_a_key_does_not_create_it(probe):
    assert probe["blocked_does_not_insert"] is True


def test_expired_entries_are_dropped(probe):
    assert probe["expired_dropped"] is True


def test_oversized_username_is_refused(probe):
    assert probe["oversized_username"] == 400


def test_oversized_password_is_refused(probe):
    assert probe["oversized_password"] == 400


def test_normal_lengths_are_not_refused(probe):
    # 400 here would mean the new bound rejects legitimate credentials.
    assert probe["normal_lengths"] != 400
