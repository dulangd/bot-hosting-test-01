"""Bot-Hosting production entrypoint.

The panel entry file remains main.py. The v2 runtime is implemented in
main_v2.py and uses bot_hosting_core.py for the original bootstrap helpers.
"""

from __future__ import annotations

from main_v2 import run


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(f"[FATAL] {exc}", flush=True)
        raise SystemExit(1)
