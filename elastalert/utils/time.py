import datetime
import json
import logging
from typing import Union

import dateutil
import pytz

log = logging.getLogger(__name__)


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, "isoformat"):
            return obj.isoformat()
        else:
            return json.JSONEncoder.default(self, obj)


def ts_to_dt(timestamp: str) -> datetime.datetime:
    if isinstance(timestamp, datetime.datetime):
        return timestamp
    dt = dateutil.parser.parse(timestamp)
    # Implicitly convert local timestamps to UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=pytz.utc)
    return dt


def dt_to_ts(dt: datetime.datetime) -> str:
    if not isinstance(dt, datetime.datetime):
        log.warning("Expected datetime, got %s" % (type(dt)))
        return dt
    ts = dt.isoformat()
    # Round microseconds to milliseconds
    if dt.tzinfo is None:
        # Implicitly convert local times to UTC
        return ts + "Z"
    # isoformat() uses microsecond accuracy and timezone offsets
    # but we should try to use millisecond accuracy and Z to indicate UTC
    return ts.replace("000+00:00", "Z").replace("+00:00", "Z")


def ts_to_dt_with_format(timestamp, ts_format):
    if isinstance(timestamp, datetime.datetime):
        return timestamp
    dt = datetime.datetime.strptime(timestamp, ts_format)
    # Implicitly convert local timestamps to UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=dateutil.tz.tzutc())
    return dt


def dt_to_ts_with_format(dt, ts_format):
    if not isinstance(dt, datetime.datetime):
        log.warning("Expected datetime, got %s" % (type(dt)))
        return dt
    ts = dt.strftime(ts_format)
    return ts


def ts_now() -> datetime.datetime:
    return datetime.datetime.utcnow().replace(tzinfo=dateutil.tz.tzutc())


def inc_ts(timestamp, milliseconds=1):
    """Increment a timestamp by milliseconds."""
    dt = ts_to_dt(timestamp)
    dt += datetime.timedelta(milliseconds=milliseconds)
    return dt_to_ts(dt)


def pretty_ts(timestamp: Union[str, datetime.datetime], tz=True) -> str:
    """Pretty-format the given timestamp (to be printed or logged hereafter).
    If tz, the timestamp will be converted to local time.
    Format: YYYY-MM-DD HH:MM TZ"""
    dt = timestamp
    if not isinstance(timestamp, datetime.datetime):
        dt = ts_to_dt(timestamp)
    if tz:
        dt = dt.astimezone(dateutil.tz.tzlocal())
    return dt.strftime("%Y-%m-%d %H:%M %Z")


def ts_add(ts, td):
    """ Allows a timedelta (td) add operation on a string timestamp (ts) """
    return dt_to_ts(ts_to_dt(ts) + td)


def seconds(td):
    return td.seconds + td.days * 24 * 3600


def total_seconds(dt):
    # For python 2.6 compatability
    if dt is None:
        return 0
    elif hasattr(dt, "total_seconds"):
        return dt.total_seconds()
    else:
        return (
            dt.microseconds + (dt.seconds + dt.days * 24 * 3600) * 10 ** 6
        ) / 10 ** 6


def dt_to_int(dt):
    dt = dt.replace(tzinfo=None)
    return int(total_seconds((dt - datetime.datetime.utcfromtimestamp(0))) * 1000)


def unixms_to_dt(ts):
    return unix_to_dt(float(ts) / 1000)


def unix_to_dt(ts):
    dt = datetime.datetime.utcfromtimestamp(float(ts))
    dt = dt.replace(tzinfo=dateutil.tz.tzutc())
    return dt


def dt_to_unix(dt):
    return int(
        total_seconds(dt - datetime.datetime(1970, 1, 1, tzinfo=dateutil.tz.tzutc()))
    )


def dt_to_unixms(dt):
    return int(dt_to_unix(dt) * 1000)
