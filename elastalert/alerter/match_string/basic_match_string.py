import json

from elastalert.utils.time import DateTimeEncoder
from elastalert.utils.util import lookup_es_key


class BasicMatchString:
    """ Creates a string containing fields in match for the given rule. """

    def __init__(self, rule, match):
        self.rule = rule
        self.match = match

    def _ensure_new_line(self):
        while self.text[-2:] != "\n\n":
            self.text += "\n"

    def _create_custom_alert_text(self, event=None, alert_text_key="alert_text"):
        if event is None:
            event = self.match
        missing = self.rule.get("alert_missing_value", "<MISSING VALUE>")
        alert_text = str(self.rule.get(alert_text_key, ""))

        if alert_text_key + "_args" in self.rule:
            alert_text_args = self.rule.get(alert_text_key + "_args")
            alert_text_values = [lookup_es_key(event, arg) for arg in alert_text_args]
            # Support referencing other top-level rule properties
            # This technically may not work if there is a top-level rule property with the same name
            # as an es result key, since it would have been matched in the lookup_es_key call above
            for i, text_value in enumerate(alert_text_values):
                if text_value is None:
                    alert_value = self.rule.get(alert_text_args[i])
                    if alert_value:
                        alert_text_values[i] = alert_value

            alert_text_values = [
                missing if val is None else val for val in alert_text_values
            ]
            alert_text = alert_text.format(*alert_text_values)
        elif alert_text_key + "_kw" in self.rule:
            kw = {}
            for name, kw_name in list(self.rule.get("alert_text_kw").items()):
                val = lookup_es_key(self.match, name)

                # Support referencing other top-level rule properties
                # This technically may not work if there is a top-level rule property with the same name
                # as an es result key, since it would have been matched in the lookup_es_key call above
                if val is None:
                    val = self.rule.get(name)

                kw[kw_name] = missing if val is None else val
            alert_text = alert_text.format(**kw)
        else:
            alert_text = alert_text.format(**event)
        return alert_text

    def _add_custom_alert_text(self):
        self.text += self._create_custom_alert_text()

    def _add_rule_text(self):
        self.text += self.rule["type"].get_match_str(self.match)

    def _add_top_counts(self):
        for key, counts in list(self.match.items()):
            if key.startswith("top_events_"):
                self.text += "%s:\n" % (key[11:])
                top_events = list(counts.items())

                if not top_events:
                    self.text += "No events found.\n"
                else:
                    top_events.sort(key=lambda x: x[1], reverse=True)
                    for term, count in top_events:
                        self.text += "%s: %s\n" % (term, count)

                self.text += "\n"

    def _add_match_items(self):
        match_items = list(self.match.items())
        match_items.sort(key=lambda x: x[0])
        for key, value in match_items:
            if key.startswith("top_events_"):
                continue
            value_str = str(value)
            value_str.replace("\\n", "\n")
            if type(value) in [list, dict]:
                try:
                    value_str = self._pretty_print_as_json(value)
                except TypeError:
                    # Non serializable object, fallback to str
                    pass
            self.text += "%s: %s\n" % (key, value_str)

    def _pretty_print_as_json(self, blob):
        try:
            return json.dumps(
                blob, cls=DateTimeEncoder, sort_keys=True, indent=4, ensure_ascii=False
            )
        except UnicodeDecodeError:
            # This blob contains non-unicode, so lets pretend it's Latin-1 to show something
            return json.dumps(
                blob,
                cls=DateTimeEncoder,
                sort_keys=True,
                indent=4,
                encoding="Latin-1",
                ensure_ascii=False,
            )

    def __str__(self):
        self.text = ""
        if "alert_text" not in self.rule:
            self.text += self.rule["name"] + "\n\n"

        self._add_custom_alert_text()
        self._ensure_new_line()
        if self.rule.get("alert_text_type") != "alert_text_only":
            self._add_rule_text()
            self._ensure_new_line()
            if self.rule.get("top_count_keys"):
                self._add_top_counts()
            if self.rule.get("alert_text_type") != "exclude_fields":
                if "related_events" in self.match:
                    related_events = self.match["related_events"]
                    del self.match["related_events"]
                    alert_text_related_event_text = str(
                        self.rule.get("alert_text_related_event_text", "")
                    )
                    if alert_text_related_event_text == "":
                        self.text += "\n----------------------------------------\n"
                        self._add_match_items()
                    else:
                        self.text += self._create_custom_alert_text(
                            self.match, "alert_text_related_event_text"
                        )

                    for related_event in related_events:
                        if alert_text_related_event_text == "":
                            self.text += "\n----------------------------------------\n"
                            self.match = related_event
                            self._add_match_items()
                        else:
                            self.text += self._create_custom_alert_text(
                                related_event, "alert_text_related_event_text"
                            )
                else:
                    self._add_match_items()
        return self.text
