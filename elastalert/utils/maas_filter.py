import operator
from abc import ABC, abstractmethod
from typing import Callable, Dict, Tuple, TypeVar

from elastalert.exceptions import EAException
from elastalert.utils.util import get_module

T = TypeVar("T", str, bytes, float)


class Filter(ABC):
    """ Simple Filter for filtering non-anomaly data. """

    @property
    @abstractmethod
    def default_setting(self) -> (Callable[[T, T], bool], T):
        """ Default Settings for Filter if no Parameters were supplied """
        pass

    @property
    @abstractmethod
    def condition_mapper(self) -> Dict[str, Tuple[Callable[[T, T], bool], T]]:
        """ Condition Mapper used for selecting the condition for the Filter """
        pass

    def __init__(self, condition: str, condition_value):
        default_condition, default_value = self.default_setting
        self.condition, self.value_type = self.condition_mapper.get(condition) or (
            default_condition,
            None,
        )
        self.condition_value = (
            condition_value if condition_value is not None else default_value
        )
        if self.value_type is None:
            self.value_type = type(self.condition_value)

    def execute(self, filter_field) -> bool:
        """ Executes the supplied filter for the received Data """
        return self.condition(self.value_type(filter_field), self.condition_value)


class ValueFilter(Filter):
    """ Flat Value Filter that operates on only one value"""

    @property
    def default_setting(self):
        """ Default check if value equals 1.0"""
        return operator.eq, 1.0

    @property
    def condition_mapper(self):

        return {
            "equals": (operator.eq, None),
            "not_equals": (operator.ne, None),
            "greater": (operator.gt, float),
            "lower": (operator.lt, float),
            "lower_equals": (operator.le, float),
            "greater_equals": (operator.ge, float),
        }


class FilterMapper:
    """
    Mapper that returns the Filter depending on the supplied value.
    Also allows dynamic code loading with get_module.
    """

    items = {"value": ValueFilter}

    @classmethod
    def get(cls, item: str, default=ValueFilter):

        if item is None:
            return default

        mapped_item = cls.items[item] if item in cls.items else get_module(item)

        if not issubclass(mapped_item, Filter):
            raise EAException(
                "Mapped item {} is not of subclass of Filter".format(mapped_item)
            )

        return mapped_item
