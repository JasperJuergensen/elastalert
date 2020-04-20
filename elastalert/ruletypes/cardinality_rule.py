from elastalert.exceptions import EAException
from elastalert.queries.elasticsearch_query import ElasticsearchQuery
from elastalert.queries.query_factory import QueryFactory
from elastalert.ruletypes import RuleType
from elastalert.utils.time import dt_to_ts, pretty_ts, ts_to_dt
from elastalert.utils.util import hashable, lookup_es_key


class CardinalityRule(RuleType):
    """ A rule that matches if cardinality of a field is above or below a threshold within a timeframe """

    required_options = frozenset(["timeframe", "cardinality_field"])

    def init_query_factory(self):
        return QueryFactory(
            ElasticsearchQuery, self.rule_config, self.add_data, self.es
        )

    def __init__(self, *args):
        super(CardinalityRule, self).__init__(*args)
        if "max_cardinality" not in self.rules and "min_cardinality" not in self.rules:
            raise EAException(
                "CardinalityRule must have one of either max_cardinality or min_cardinality"
            )
        self.ts_field = self.rules.get("timestamp_field", "@timestamp")
        self.cardinality_field = self.rules["cardinality_field"]
        self.cardinality_cache = {}
        self.first_event = {}
        self.timeframe = self.rules["timeframe"]

    def add_data(self, data):
        qk = self.rules.get("query_key")
        for event in data:
            if qk:
                key = hashable(lookup_es_key(event, qk))
            else:
                # If no query_key, we use the key 'all' for all events
                key = "all"
            self.cardinality_cache.setdefault(key, {})
            self.first_event.setdefault(key, lookup_es_key(event, self.ts_field))
            value = hashable(lookup_es_key(event, self.cardinality_field))
            if value is not None:
                # Store this timestamp as most recent occurence of the term
                self.cardinality_cache[key][value] = lookup_es_key(event, self.ts_field)
                self.check_for_match(key, event)

    def check_for_match(self, key, event, gc=True):
        # Check to see if we are past max/min_cardinality for a given key
        time_elapsed = lookup_es_key(event, self.ts_field) - self.first_event.get(
            key, lookup_es_key(event, self.ts_field)
        )
        timeframe_elapsed = time_elapsed > self.timeframe
        if len(self.cardinality_cache[key]) > self.rules.get(
            "max_cardinality", float("inf")
        ) or (
            len(self.cardinality_cache[key])
            < self.rules.get("min_cardinality", float("-inf"))
            and timeframe_elapsed
        ):
            # If there might be a match, run garbage collect first, as outdated terms are only removed in GC
            # Only run it if there might be a match so it doesn't impact performance
            if gc:
                self.garbage_collect(lookup_es_key(event, self.ts_field))
                self.check_for_match(key, event, False)
            else:
                self.first_event.pop(key, None)
                self.add_match(event)

    def garbage_collect(self, timestamp):
        """ Remove all occurrence data that is beyond the timeframe away """
        for qk, terms in list(self.cardinality_cache.items()):
            for term, last_occurence in list(terms.items()):
                if timestamp - last_occurence > self.rules["timeframe"]:
                    self.cardinality_cache[qk].pop(term)

            # Create a placeholder event for if a min_cardinality match occured
            if "min_cardinality" in self.rules:
                event = {self.ts_field: timestamp}
                if "query_key" in self.rules:
                    event.update({self.rules["query_key"]: qk})
                self.check_for_match(qk, event, False)

    def get_match_str(self, match):
        lt = self.rules.get("use_local_time")
        starttime = pretty_ts(
            dt_to_ts(
                ts_to_dt(lookup_es_key(match, self.ts_field)) - self.rules["timeframe"]
            ),
            lt,
        )
        endtime = pretty_ts(lookup_es_key(match, self.ts_field), lt)
        if "max_cardinality" in self.rules:
            message = (
                "A maximum of %d unique %s(s) occurred since last alert or between %s and %s\n\n"
                % (
                    self.rules["max_cardinality"],
                    self.rules["cardinality_field"],
                    starttime,
                    endtime,
                )
            )
        else:
            message = (
                "Less than %d unique %s(s) occurred since last alert or between %s and %s\n\n"
                % (
                    self.rules["min_cardinality"],
                    self.rules["cardinality_field"],
                    starttime,
                    endtime,
                )
            )
        return message
