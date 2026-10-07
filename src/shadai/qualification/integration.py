"""Resolve the private CI Redis URL before exec; credentials never enter command logs."""

import os
from urllib.parse import urlsplit, urlunsplit


def main():
    from shadai.config import load_config

    config = load_config()
    parsed = urlsplit(config.database.redis_url)
    if not parsed.hostname or parsed.scheme not in {"redis", "rediss"}:
        raise ValueError("Explicit configured Redis endpoint is required")
    # Dedicated fixture refuses an initially nonempty database and removes only
    # its exact keys. Neither this wrapper nor the fixture calls FLUSHDB.
    os.environ["SHADAI_REDIS_QUEUE_TEST_URL"] = urlunsplit(parsed._replace(path="/14"))
    os.execvp(
        "python", ["python", "-m", "pytest", "-q", "-m", "integration and not redis_pressure", "-p", "no:cacheprovider"]
    )


if __name__ == "__main__":
    main()
