"""Bot-Hosting v2 entrypoint.

The known-working ``main.py`` remains the bootstrap baseline. v2 adds:
- three independent Registry endpoint identities;
- the existing endpoint client identities are preserved; the historical default identity is not replaced;
- additional endpoint client identities are stable and persisted once created;
- independent endpoint heartbeat/re-registration;
- one stable individual subscription URL containing all three endpoints;
- one public TCP port shared by the subscription HTTP path and REALITY traffic;
- shared physical-instance traffic ownership with no triple counting.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import signal
import socket
import subprocess
import sys
from pathlib import Path

import main as core
from bot_hosting_agent import (
    SubscriptionMux,
    build_endpoints,
    ensure_endpoint_clients,
    start_agent,
    subscription_token,
    verified_country,
)

CLIENT_LINKS = core.STATE_DIR / "client-links.txt"
TRAFFIC_LOG = core.STATE_DIR / "traffic-events.log"


def configure_private_traffic_log(config: dict) -> None:
    if os.environ.get("RR_TRAFFIC_TRACKING", "1") == "0":
        config["log"] = {"level": "error", "output": "none"}