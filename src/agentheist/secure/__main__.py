"""Run the secure helpdesk over streamable HTTP: `uv run python -m agentheist.secure`.

All settings come from AGENTHEIST_SECURE_* environment variables (see src/agentheist/secure/README.md).
Set AGENTHEIST_SECURE_DEBUG=1 to see full tracebacks for unexpected startup errors.
"""

import logging
import os
import sys

import uvicorn

from agentheist.secure.auth import ConfigurationError
from agentheist.secure.config import SecureConfig
from agentheist.secure.helpdesk import build_server

logger = logging.getLogger("agentheist.secure")


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    try:
        config = SecureConfig.from_env()
        server = build_server(config)
    except ConfigurationError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        if os.environ.get("AGENTHEIST_SECURE_DEBUG") == "1":
            raise
        print(f"Startup failed ({type(exc).__name__}). Set AGENTHEIST_SECURE_DEBUG=1 for details.", file=sys.stderr)
        return 1
    for warning in config.startup_warnings():
        logger.warning(warning)
    app = server.streamable_http_app(host=config.host)
    uvicorn.run(app, host=config.host, port=config.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
