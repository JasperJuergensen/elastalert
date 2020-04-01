import copy

from elastalert.ruletypes import FrequencyRule
from elastalert.utils.time import pretty_ts, dt_to_ts, ts_to_dt
from elastalert.utils.event_window import EventWindow


class FlatlineRule(FrequencyRule):
    """ A rule that matches when there is a low number of events given a timeframe. """
    required_options = frozenset(['timeframe', 'threshold'])

    def __init__(self, *args):
        super(FlatlineRule, self).__init__(*args)
        self.threshold = self.rules['threshold']

        # Dictionary mapping query keys to the first events
        self.first_event = {}

    def check_for_match(self, key, end=True):
        # This function gets called between every added document with end=True after the last
        # We ignore the calls before the end because it may trigger false positives
        if not end:
            return

        most_recent_ts = self.get_ts(self.occurrences[key].data[-1])
        if self.first_event.get(key) is None:
            self.first_event[key] = most_recent_ts

        # Don't check for matches until timeframe has elapsed
        if most_recent_ts - self.first_event[key] < self.rules['timeframe']:
            return

        # Match if, after removing old events, we hit num_events
        count = self.occurrences[key].count()
        if count < self.rules['threshold']:
            # Do a deep-copy, otherwise we lose the datetime type in the timestamp field of the last event
            event = copy.deepcopy(self.occurrences[key].data[-1][0])
            event.update(key=key, count=count)
            self.add_match(event)

            if not self.rules.get('forget_keys'):
                # After adding this match, leave the occurrences windows alone since it will
                # be pruned in the next add_data or garbage_collect, but reset the first_event
                # so that alerts continue to fire until the threshold is passed again.
                least_recent_ts = self.get_ts(self.occurrences[key].data[0])
                timeframe_ago = most_recent_ts - self.rules['timeframe']
                self.first_event[key] = min(least_recent_ts, timeframe_ago)
            else:
                # Forget about this key until we see it again
                self.first_event.pop(key)
                self.occurrences.pop(key)

    def get_match_str(self, match):
        ts = match[self.rules['timestamp_field']]
        lt = self.rules.get('use_local_time')
        message = 'An abnormally low number of events occurred around %s.\n' % (pretty_ts(ts, lt))
        message += 'Between %s and %s, there were less than %s events.\n\n' % (
            pretty_ts(dt_to_ts(ts_to_dt(ts) - self.rules['timeframe']), lt),
            pretty_ts(ts, lt),
            self.rules['threshold']
        )
        return message

    def garbage_collect(self, ts):
        # We add an event with a count of zero to the EventWindow for each key. This will cause the EventWindow
        # to remove events that occurred more than one `timeframe` ago, and call onRemoved on them.
        default = ['all'] if 'query_key' not in self.rules else []
        for key in list(self.occurrences.keys()) or default:
            self.occurrences.setdefault(
                key,
                EventWindow(self.rules['timeframe'], getTimestamp=self.get_ts)
            ).append(
                ({self.ts_field: ts}, 0)
            )
            self.first_event.setdefault(key, ts)
            self.check_for_match(key)
