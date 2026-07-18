"""Time helpers.

Convention: we STORE everything in UTC (unambiguous, no DST) and only convert to
IST at the edge — when formatting a timestamp for a human to read. Never store IST.
"""

from datetime import datetime, timezone, timedelta

# India Standard Time = UTC+5:30, no daylight saving.
IST = timezone(timedelta(hours=5, minutes=30))


def utc_now() -> datetime:
    """Current instant, timezone-aware, in UTC. Use this instead of datetime.now()
    for anything we compute in Python (e.g. token expiry = utc_now() + ttl)."""
    return datetime.now(timezone.utc)


def to_ist(dt: datetime) -> datetime:
    """Convert a datetime to IST for display. A naive datetime (no tzinfo) is
    assumed to be UTC — which is what Postgres TIMESTAMPTZ round-trips as."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(IST)
