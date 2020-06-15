import datetime
from typing import Tuple

from blist import sortedlist
from elastalert.utils.util import new_get_event_ts


class EventWindow:
    """ A container for hold event counts for rules which need a chronological ordered event window. """

    def __init__(
        self,
        timeframe: datetime.timedelta,
        on_removed: callable = None,
        get_timestamp: callable = new_get_event_ts("@timestamp"),
    ):
        self.timeframe = timeframe
        self.on_removed = on_removed
        self.get_ts = get_timestamp
        self.data = sortedlist(key=self.get_ts)
        self.running_count = 0

    def clear(self):
        """Clears the event window"""
        self.data = sortedlist(key=self.get_ts)
        self.running_count = 0

    def clean_old_events(self):
        """Removes old events"""
        while self.data and self.duration() >= self.timeframe:
            oldest = self.data[0]
            self.data.remove(oldest)
            self.running_count -= oldest[1]
            self.on_removed and self.on_removed(oldest)

    def append(self, event: Tuple[dict, int]):
        """ Add an event to the window. Event should be of the form (dict, count).
        This will also pop the oldest events and call onRemoved on them until the
        window size is less than timeframe. """
        self.data.add(event)
        self.running_count += event[1]
        self.clean_old_events()

    def duration(self) -> datetime.timedelta:
        """ Get the size in timedelta of the window. """
        if not self.data:
            return datetime.timedelta(0)
        return self.get_ts(self.data[-1]) - self.get_ts(self.data[0])


class CountEventWindow(EventWindow):
    """ A container for hold event counts for rules which need a chronological ordered event window. """

    def count(self):
        """ Count the number of events in the window. """
        return self.running_count
