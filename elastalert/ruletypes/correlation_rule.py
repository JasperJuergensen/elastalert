import logging
from typing import List

from elastalert.queries.elasticsearch_query import ElasticsearchQuery
from elastalert.queries.query_factory import QueryFactory
from elastalert.ruletypes import RuleType
from elastalert.utils.state_machine import StateMachine
from elastalert.utils.time import ts_to_dt
from elastalert.utils.util import hashable, lookup_es_key
from fysom import Canceled

log = logging.getLogger(__name__)


class CorrelationRule(RuleType):
    """Correlation rule"""

    required_options = frozenset(["state_machine", "event_name_field"])

    def __init__(self, rule_config, *args, **kwargs):
        super().__init__(rule_config, *args, **kwargs)
        self.state_machines = dict()
        self.start_events = list()

        self.event_name_field = self.rule_config["event_name_field"]

        self.remove_on_failed_precondition = self.rule_config.get(
            "remove_on_failed_precondition", True
        )
        self.alert_on_final = self.rule_config.get("alert_on_final", True)
        self.remove_on_not_accepted = self.rule_config.get(
            "remove_on_not_accepted", True
        )
        self.multiple_alerts = self.rule_config.get("multiple_alerts", True)
        if self.event_name_field not in self.rule_config["include"]:
            self.rule_config["include"].append(self.event_name_field)

        self.ts_field = self.rules.get("timestamp_field", "@timestamp")

    def init_query_factory(self) -> QueryFactory:
        return QueryFactory(
            ElasticsearchQuery, self.rule_config, self.add_data, self.es
        )

    def remove_state_machine(self, qk, idx: int):
        if qk in self.state_machines:
            del self.state_machines[qk][idx]
            if len(self.state_machines[qk]) == 0:
                self.state_machines.pop(qk)

    def add_data(self, data: List[dict]):
        for event in data:
            skip_cache = dict()
            to_remove = dict()
            qk = self.rules.get("query_key", "all")
            if qk != "all":
                qk = hashable(lookup_es_key(event, qk))
                if qk is None:
                    qk = "other"
            state_machines = self.state_machines.setdefault(qk, list())
            for idx, state_machine in enumerate(state_machines):
                if state_machine.can(event[self.event_name_field]):
                    try:
                        state_machine.trigger(
                            event[self.event_name_field],
                            timestamp=ts_to_dt(lookup_es_key(event, self.ts_field)),
                        )
                    except Canceled as e:
                        # precondition not matched
                        log.debug("Precondition not matched: %s", e)
                        if self.remove_on_failed_precondition:
                            state_machine.remove_event(event[self.event_name_field])
                    else:
                        if state_machine.is_finished():
                            if self.alert_on_final:
                                if self.multiple_alerts or (
                                    qk not in skip_cache
                                    or state_machine.current not in skip_cache[qk]
                                ):
                                    extra_info = {"final_state": state_machine.current}
                                    match = dict(
                                        list(event.items()) + list(extra_info.items())
                                    )
                                    self.add_match(match)
                                    skip_cache.setdefault(qk, list()).append(
                                        state_machine.current
                                    )
                    if not state_machine.can_any():
                        to_remove.setdefault(qk, []).append(idx)
                elif not self.alert_on_final:
                    # alert if event is not accepted by state machine
                    if self.multiple_alerts or (
                        qk not in skip_cache
                        or state_machine.current not in skip_cache[qk]
                    ):
                        extra_info = {"current_state": state_machine.current}
                        match = dict(list(event.items()) + list(extra_info.items()))
                        self.add_match(match)
                        skip_cache.setdefault(qk, list()).append(state_machine.current)
                        if self.remove_on_not_accepted:
                            self.remove_state_machine(qk, idx)
            state_machine = StateMachine(self.rule_config)
            if state_machine.can(event[self.event_name_field]):
                # event is a start event
                state_machine.trigger(event[self.event_name_field])
                self.state_machines[qk].append(state_machine)
            for qk, idxs in to_remove.items():
                for idx in sorted(set(idxs), reverse=True):
                    self.remove_state_machine(qk, idx)
