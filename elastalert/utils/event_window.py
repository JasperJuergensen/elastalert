import datetime

from blist import sortedlist

from elastalert.utils.util import new_get_event_ts


class EventWindow():
    """ A container for hold event counts for rules which need a chronological ordered event window. """

    def __init__(self, timeframe, onRemoved=None, getTimestamp=new_get_event_ts('@timestamp')):
        self.timeframe = timeframe
        self.onRemoved = onRemoved
        self.get_ts = getTimestamp
        self.data = sortedlist(key=self.get_ts)
        self.running_count = 0

    def clear(self):
        self.data = sortedlist(key=self.get_ts)
        self.running_count = 0

    def append(self, event):
        """ Add an event to the window. Event should be of the form (dict, count).
        This will also pop the oldest events and call onRemoved on them until the
        window size is less than timeframe. """
        self.data.add(event)
        self.running_count += event[1]

        while self.duration() >= self.timeframe:
            oldest = self.data[0]
            self.data.remove(oldest)
            self.running_count -= oldest[1]
            self.onRemoved and self.onRemoved(oldest)

    def duration(self):
        """ Get the size in timedelta of the window. """
        if not self.data:
            return datetime.timedelta(0)
        return self.get_ts(self.data[-1]) - self.get_ts(self.data[0])

    def count(self):
        """ Count the number of events in the window. """
        return self.running_count

    def mean(self):
        """ Compute the mean of the value_field in the window. """
        if len(self.data) > 0:
            datasum = 0
            datalen = 0
            for dat in self.data:
                if "placeholder" not in dat[0]:
                    datasum += dat[1]
                    datalen += 1
            if datalen > 0:
                return datasum / float(datalen)
            return None
        else:
            return None

    def __iter__(self):
        return iter(self.data)

    def append_middle(self, event):
        """ Attempt to place the event in the correct location in our deque.
        Returns True if successful, otherwise False. """
        rotation = 0
        ts = self.get_ts(event)

        # Append left if ts is earlier than first event
        if self.get_ts(self.data[0]) > ts:
            self.data.appendleft(event)
            self.running_count += event[1]
            return

        # Rotate window until we can insert event
        while self.get_ts(self.data[-1]) > ts:
            self.data.rotate(1)
            rotation += 1
            if rotation == len(self.data):
                # This should never happen
                return
        self.data.append(event)
        self.running_count += event[1]
        self.data.rotate(-rotation)
