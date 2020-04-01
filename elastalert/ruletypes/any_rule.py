from elastalert.ruletypes import RuleType


class AnyRule(RuleType):
    """ A rule that will match on any input data """

    def add_data(self, data):
        for datum in data:
            self.add_match(datum)
