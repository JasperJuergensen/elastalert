from elastalert.ruletypes.compare_rule import CompareRule
from elastalert.utils.util import lookup_es_key


class WhitelistRule(CompareRule):
    """ A CompareRule where the compare function checks a given term against a whitelist """

    required_options = frozenset(["compare_key", "whitelist", "ignore_null"])

    def __init__(self, rules, *args, **kwargs):
        super(WhitelistRule, self).__init__(rules, *args, **kwargs)
        self.expand_entries("whitelist")

    def compare(self, event):
        term = lookup_es_key(event, self.rules["compare_key"])
        if term is None:
            return not self.rules["ignore_null"]
        return term not in self.rules["whitelist"]

    def garbage_collect(self, timestamp):
        pass
