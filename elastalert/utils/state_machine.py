import datetime
import logging
import types
from typing import Tuple

from elastalert.utils.time import pretty_ts, ts_now
from fysom import FysomGlobal, FysomGlobalMixin

log = logging.getLogger(__name__)


class StateMachine(FysomGlobalMixin, object):
    def __init__(self, rule_config: dict, *args, **kwargs):
        self.state = None
        final = rule_config["state_machine"]["final_states"]
        events = rule_config["state_machine"]["events"]
        conditions = rule_config["state_machine"].get("conditions", list())
        for cond_id, condition in enumerate(conditions):
            cond_name = condition.get("name", f"cond{cond_id}")
            self.add_cond_fn(cond_name, condition)
            for event in events:
                if event["dst"] == condition["dst"]:
                    event.setdefault("cond", list()).append(cond_name)
        self.GSM = FysomGlobal(
            state_field="state", initial="ST", final=final, events=events
        )
        self.log = list()
        super().__init__(*args, **kwargs)

    def add_cond_fn(self, fn_name: str, condition: dict):
        def fn(self, e):
            for transaction in reversed(self.log):
                if transaction[2] == condition["src"]:
                    start_time = transaction[3]
                    break
            else:
                # never seen condition transaction
                return True
            end_time = e.kwargs.get("timestamp", ts_now())
            if (end_time - start_time) > datetime.timedelta(**condition["timeframe"]):
                return False
            return True

        setattr(self, fn_name, types.MethodType(fn, self))

    def onchangestate(self, e):
        log.debug(
            "event: %s, src: %s, dst: %s, ts: %s",
            e.event,
            e.src,
            e.dst,
            pretty_ts(e.kwargs.get("timestamp", ts_now())),
        )
        self.log.append((e.event, e.src, e.dst, e.kwargs.get("timestamp", ts_now())))

    def can_any(self) -> bool:
        for event in self.GSM._map:
            if self.can(event):
                return True
        return False

    def is_finished(self) -> bool:
        if isinstance(self.GSM._final, list):
            return self.current in self.GSM._final
        else:
            return super().is_finished()

    def remove_event(self, event, src=None):
        if not src:
            src = self.current
        ev = self.GSM._map.get(event)
        if ev:
            if src in ev["src"]:
                ev["src"].remove(src)
            log.debug("Removed event %s (%s -> %s)", event, src, ev["dst"])
            if len(ev["src"]) == 0:
                del self.GSM._map[event]
