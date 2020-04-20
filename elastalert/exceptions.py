class EAException(Exception):
    """Base elastalert exception"""


class EAConfigException(EAException):
    """This exception is thrown when the configuration is not correct"""


class EARuntimeException(EAException):
    """This exception is thrown when while running a rule an exception aborts the rule execution"""

    def __init__(
        self,
        msg: str,
        rule: str = None,
        query: dict = None,
        original_exception: Exception = None,
        *args
    ):
        super().__init__(*args)
        self.msg = msg
        self.original_exception = original_exception
        self.rule_name = rule
        self.query = query
