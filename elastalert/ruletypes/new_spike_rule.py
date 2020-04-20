import datetime
from typing import Dict, List

from elastalert.exceptions import EAConfigException
from elastalert.queries.elasticsearch_query import (
    ElasticsearchCountQuery,
    ElasticsearchQuery,
    ElasticsearchTermQuery,
)
from elastalert.queries.query_factory import QueryFactory
from elastalert.ruletypes import RuleType
from elastalert.utils.event_window import CountEventWindow
from elastalert.utils.util import hashable, lookup_es_key


class Spike(RuleType):
    def __init__(self, rule_config, *args, **kwargs):
        super().__init__(rule_config, *args, **kwargs)
        self.timeframe = self.rule_config["timeframe"]
        self.gap_timeframe = self.rule_config.get(
            "gap_timeframe", datetime.timedelta(seconds=0)
        )
        self.ref_count = self.rule_config.get("ref_count", 1)
        if self.ref_count < 1:
            raise EAConfigException("ref_count must be >= 1")
        # TODO get spike_height_ref with a default and change the check after this comment
        if "spike_height_ref" in self.rule_config and self.ref_count == 1:
            raise EAConfigException("If spike_height_ref is set, ref_count must be > 1")
        self.windows = dict()

    def init_query_factory(self) -> QueryFactory:
        if self.rule_config.get("use_count_query"):
            return QueryFactory(
                ElasticsearchCountQuery, self.rule_config, self.add_count_data
            )
        elif self.rule_config.get("use_terms_query"):
            return QueryFactory(
                ElasticsearchTermQuery, self.rule_config, self.add_terms_data
            )
        else:
            return QueryFactory(ElasticsearchQuery, self.rule_config, self.add_data)

    def garbage_collect(self, timestamp):
        pass  # TODO

    def init_windows(self, qk):
        self.windows[qk] = [CountEventWindow(self.timeframe)]
        last_window = self.windows[qk][0]
        for i in range(self.ref_count - 1):
            self.windows[qk].append(
                CountEventWindow(self.timeframe, last_window.append)
            )
            last_window = self.windows[qk][-1]

    def handle_event(self, event: dict, count: int, qk: str = "all"):
        if qk not in self.windows:
            self.init_windows(qk)

    def add_data(self, data: List[dict]):
        for event in data:
            qk = self.rule_config.get("query_key", "all")
            if qk != "all":
                qk = hashable(lookup_es_key(event, qk))
                if qk is None:
                    qk = "other"
            self.handle_event(event, 1, qk)

    def add_count_data(self, counts: Dict[datetime.datetime, int]):
        pass  # TODO count

    def add_terms_data(self, terms: Dict[datetime.datetime, List[dict]]):
        pass  # TODO
