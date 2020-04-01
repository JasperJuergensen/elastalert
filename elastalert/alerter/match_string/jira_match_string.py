from elastalert.alerter.match_string.basic_match_string import BasicMatchString


class JiraFormattedMatchString(BasicMatchString):
    def _add_match_items(self):
        match_items = dict(
            [
                (x, y)
                for x, y in list(self.match.items())
                if not x.startswith("top_events_")
            ]
        )
        json_blob = self._pretty_print_as_json(match_items)
        preformatted_text = "{{code}}{0}{{code}}".format(json_blob)
        self.text += preformatted_text
