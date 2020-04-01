import logging

from elastalert.ruletypes.compare_rule import CompareRule
from elastalert.utils.util import lookup_es_key, hashable

log = logging.getLogger(__name__)


class ChangeRule(CompareRule):
    """ A rule that will store values for a certain term and match if those values change """
    required_options = frozenset(['query_key', 'compound_compare_key', 'ignore_null'])
    change_map = {}
    occurrence_time = {}

    def compare(self, event):
        key = hashable(lookup_es_key(event, self.rules['query_key']))
        values = []
        log.debug(" Previous Values of compare keys  " + str(self.occurrences))
        for val in self.rules['compound_compare_key']:
            lookup_value = lookup_es_key(event, val)
            values.append(lookup_value)
        log.debug(" Current Values of compare keys   " + str(values))

        changed = False
        for val in values:
            if not isinstance(val, bool) and not val and self.rules['ignore_null']:
                return False
        # If we have seen this key before, compare it to the new value
        if key in self.occurrences:
            for idx, previous_values in enumerate(self.occurrences[key]):
                log.debug(" " + str(previous_values) + " " + str(values[idx]))
                changed = previous_values != values[idx]
                if changed:
                    break
            if changed:
                self.change_map[key] = (self.occurrences[key], values)
                # If using timeframe, only return true if the time delta is < timeframe
                if key in self.occurrence_time:
                    changed = event[self.rules['timestamp_field']] - self.occurrence_time[key] <= self.rules['timeframe']

        # Update the current value and time
        log.debug(" Setting current value of compare keys values " + str(values))
        self.occurrences[key] = values
        if 'timeframe' in self.rules:
            self.occurrence_time[key] = event[self.rules['timestamp_field']]
        log.debug("Final result of comparision between previous and current values " + str(changed))
        return changed

    def add_match(self, match):
        # TODO this is not technically correct
        # if the term changes multiple times before an alert is sent
        # this data will be overwritten with the most recent change
        change = self.change_map.get(hashable(lookup_es_key(match, self.rules['query_key'])))
        extra = {}
        if change:
            extra = {'old_value': change[0],
                     'new_value': change[1]}
            log.debug("Description of the changed records  " + str(dict(list(match.items()) + list(extra.items()))))
        super(ChangeRule, self).add_match(dict(list(match.items()) + list(extra.items())))
