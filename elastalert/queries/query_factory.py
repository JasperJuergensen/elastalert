from elastalert.queries import BaseQuery


class QueryFactory:
    def __init__(self, query_class: type, rule_config: dict, callback: callable, client=None):
        self.query_class = query_class
        self.rule_config = rule_config
        self.callback = callback
        self.persistent = {}
        self.client = client

    def get_query_instance(self) -> BaseQuery:
        return self.query_class(self.rule_config, self.callback, self.persistent, self.client)
