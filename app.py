"""Launch the local development API from either the IDE or a terminal."""
import os
from pathlib import Path
import socket
import sys

import uvicorn

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))


def main() -> int:
    host = "127.0.0.1"
    try:
        port = int(os.environ.get("SIH_API_PORT", "8000"))
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        print("SIH_API_PORT must be a port number between 1 and 65535.", file=sys.stderr)
        return 1

    # Diagnose before Uvicorn's reloader exits with a Windows socket error.
    # Windows exclusive binding also detects listeners using SO_REUSEADDR.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            option = socket.SO_EXCLUSIVEADDRUSE if os.name == "nt" else socket.SO_REUSEADDR
            probe.setsockopt(socket.SOL_SOCKET, option, 1)
            probe.bind((host, port))
    except OSError as exc:
        print(
            f"Cannot start the API on {host}:{port}: {exc}\n"
            f"Port {port} may already be in use or reserved by Windows.\n"
            "If the SIH API is already running, use its dashboard or stop that server first.\n"
            f"Original dashboard: http://{host}:{port}/\n"
            f"Simple dashboard:   http://{host}:{port}/simple/\n"
            "To identify the listener in PowerShell:\n"
            f"  Get-NetTCPConnection -LocalPort {port} -State Listen | Select-Object OwningProcess\n"
            "To choose another port, set $env:SIH_API_PORT before running app.py.\n"
            "A second SIH API also needs its own SIH_STATE_DIR to avoid sharing the database.",
            file=sys.stderr,
        )
        return 1

    # Relative configuration paths and reload watches belong to this project,
    # even when the IDE launches the file from the workspace's parent folder.
    os.chdir(PROJECT_ROOT)
    print("Starting the SIH26145 API Server in DEBUG mode...", flush=True)
    print(f"Original dashboard: http://{host}:{port}/", flush=True)
    print(f"Simple dashboard:   http://{host}:{port}/simple/", flush=True)
    uvicorn.run(
        "api.main:app",
        host=host,
        port=port,
        reload=True,
        reload_dirs=[str(PROJECT_ROOT / folder) for folder in ("api", "engine", "training")],
        log_level="debug",
        proxy_headers=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
