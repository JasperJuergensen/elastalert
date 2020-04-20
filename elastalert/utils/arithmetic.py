from math import ceil, floor, sqrt
from typing import List, Union


def mean(data: List[Union[int, float]]) -> float:
    """
    Calculates the mean over the list values
    :param data: list of values
    :return: the mean
    """
    return sum(data) / len(data)


def median(data: List[Union[int, float]]) -> float:
    """
    Calculates the median over a list of values
    :param data: list of values
    :return: the median
    """
    return percentile(data, 0.5)


def percentile(data: List[Union[int, float]], percentile: float = 0.95) -> float:
    """
    Calculates the nth percentile of a list of values
    :param data: list of values
    :param percentile: the percentile as float between 0 and 1, default is 0.95
    :return: the nth percentile
    """
    if percentile < 0 or percentile > 1:
        raise ValueError("percentile value must be between 0 and 100")
    data = sorted(data)
    k = (len(data) - 1) * percentile
    f = floor(k)
    c = ceil(k)
    if f == c:
        return float(data[int(k)])
    d0 = data[int(f)] * (c - k)
    d1 = data[int(c)] * (k - f)
    return d0 + d1


def variance(data: List[Union[int, float]]) -> float:
    """
    Calculates the variance of a list of values
    :param data: the list of values
    :return: the variance
    """
    m = mean(data)
    return sum((xi - m) ** 2 for xi in data) / len(data)


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


def interquartile_range(data: List[Union[int, float]]) -> float:
    """
    Calculates the interquartile range (q3 - q1) of a list of values
    :param data: list of values
    :return: the interquartile range
    """
    return percentile(data, 0.75) - percentile(data, 0.25)


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
    "percentiles": percentile,
    "variance": variance,
    "MAD": mad,
    "standard_derivation": standard_deviation,
    "interquartile_range": interquartile_range,
}
