from elastalert.ruletypes.compare_rule import CompareRule
from elastalert.utils.util import lookup_es_key


class BlacklistRule(CompareRule):
    """ A CompareRule where the compare function checks a given key against a blacklist """

    required_options = frozenset(["compare_key", "blacklist"])

    def __init__(self, rules, args=None):
        super(BlacklistRule, self).__init__(rules, args=None)
        self.expand_entries("blacklist")

    def compare(self, event):
        term = lookup_es_key(event, self.rules["compare_key"])
        if term in self.rules["blacklist"]:
            return True
        return False
