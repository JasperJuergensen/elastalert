from decimal import Decimal
from math import ceil, floor
from statistics import StatisticsError, mean, median, stdev, variance
from typing import List, Tuple, Union

from elastalert.exceptions import EAException
from elastalert.utils.util import get_module


def fractional_part(x: float) -> float:
    """
    Calculates the fractional part of an float using Decimal
    :param x: x
    :return: The fractional part of x
    """
    return float(Decimal(str(x)) % 1)


def percentile(
    data: List[Union[int, float]],
    percentile: float = 0.95,
    params: Tuple[
        Union[int, float], Union[int, float], Union[int, float], Union[int, float]
    ] = (0, 0, 1, 0),
) -> float:
    """
    Calculates the nth percentile of a list of values
    :param data: list of values
    :params params: The parameters a, b, c, d are used to calculate the percentile.
    :param percentile: the percentile as float between 0 and 1, default is 0.95
    :return: the nth percentile
    """
    if len(data) == 0:
        raise StatisticsError("The data list cannot be empty")
    a, b, c, d = params
    if percentile < 0 or percentile > 1:
        raise StatisticsError("percentile value must be between 0 and 100")
    data = [0] + sorted(data)
    n = len(data) - 1
    x = a + (n + b) * percentile
    if x < 1:
        # lower bound of x is 0
        x = 1
    if x > n:
        # upper bound of x is len(data) - 1 (last index)
        x = n
    fl = floor(x)
    ce = ceil(x)
    if fl == ce:
        # x is an int
        return float(data[int(x)])
    return data[fl] + (data[ce] - data[fl]) * (c + d * fractional_part(x))


def mad(data: List[Union[int, float]]) -> float:
    """
    Calculates the median absolute deviation (MAD) of a list of values
    :param data: list of values
    :return: the MAD
    """
    m = median(data)
    return median([abs(xi - m) for xi in data])


def interquartile_range(
    data: List[Union[int, float]],
    params: Tuple[
        Union[int, float], Union[int, float], Union[int, float], Union[int, float]
    ] = (0, 0, 1, 0),
) -> float:
    """
    Calculates the interquartile range (q3 - q1) of a list of values
    :param data: list of values
    :params params: The parameters a, b, c, d are used to calculate the quartiles.
    :return: the interquartile range
    """
    return percentile(data, 0.75, params) - percentile(data, 0.25, params)


def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)


class Mapping:

    items = {
        "mean": mean,
        "median": median,
        "sum": sum,
        "min": min,
        "max": max,
        "percentile": percentile,
        "variance": variance,
        "MAD": mad,
        "stdev": stdev,
        "interquartile_range": interquartile_range,
    }

    @classmethod
    def get(cls, item: str, default=None):
        if item in cls.items:
            return cls.items[item]
        else:
            try:
                return get_module(item)
            except EAException:
                return default
