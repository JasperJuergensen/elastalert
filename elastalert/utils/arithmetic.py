from decimal import Decimal
from math import ceil, floor, sqrt
from typing import List, Tuple, Union


def mean(data: List[Union[int, float]]) -> float:
    """
    Calculates the mean over the list values
    :param data: list of values
    :return: the mean
    """
    if len(data) == 0:
        raise ValueError("The data list cannot be empty")
    return sum(data) / len(data)


def median(data: List[Union[int, float]]) -> float:
    """
    Calculates the median over a list of values
    :param data: list of values
    :return: the median
    """
    return percentile(data, 1 / 2, (1 / 2, 0, 0, 1))


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
        raise ValueError("The data list cannot be empty")
    a, b, c, d = params
    if percentile < 0 or percentile > 1:
        raise ValueError("percentile value must be between 0 and 100")
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


def variance(data: List[Union[int, float]]) -> float:
    """
    Calculates the variance of a list of values
    :param data: the list of values
    :return: the variance
    """
    if len(data) < 2:
        raise ValueError("The data should have at least two elements")
    m = mean(data)
    return sum((xi - m) ** 2 for xi in data) / (len(data) - 1)


def standard_deviation(data: List[Union[int, float]]) -> float:
    """
    Calculates the standard deviation of a list of values
    :param data: list of values
    :return: the standard derivation
    """
    return sqrt(variance(data))


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


mapping = {
    "mean": mean,
    "median": median,
    "sum": sum,
    "min": min,
    "max": max,
    "percentile": percentile,
    "variance": variance,
    "MAD": mad,
    "standard_derivation": standard_deviation,
    "interquartile_range": interquartile_range,
}
