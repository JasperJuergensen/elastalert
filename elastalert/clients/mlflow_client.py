import ast
from abc import ABCMeta, abstractmethod
from typing import List

import requests
from elastalert.exceptions import EAException
from elastalert.utils.time import ts_to_dt, unix_to_dt, unixms_to_dt
from elastalert.utils.util import get_module
from pandas import DataFrame


class MaasResponse:
    """ Maas Response that describes the returned information in a format that is processable """

    @classmethod
    def from_list(cls, data: List):
        """
        Creates a List of values which describe the response of the called external Model.
        Either accepts a flat list or a list with two items and takes the second one.
        @param data: The data returned from the called external Model.
        @return:
        """
        first_elem = data[0] if data else None
        if not first_elem:
            return cls([])
        else:
            # Remove first element (is_anomaly) and take only score: mapping type = (is_anomaly, score)
            if (
                isinstance(first_elem, (list, tuple))
                and len(first_elem) == 2
                and isinstance(first_elem[0], (str, int, float))
            ):
                data = [line[1] for line in data]
            elif isinstance(first_elem, (str, int, float)):
                data = [line for line in data]
            else:
                raise EAException("Invalid Response received. It cannot be parsed.")
        return cls(data)

    def __init__(self, data: List):
        self.filtered_data = data

    def __iter__(self):
        """
        Makes the encapsulated list iterable
        @return:
        """
        return iter(self.filtered_data)


class MaasClient(metaclass=ABCMeta):
    """
    Describes an abstract structure for defining a Maas-Client Implementation
    """

    def __init__(self, url, columns_mapping):
        self.url = url
        self.columns = None
        self.columns_rename = None
        self.columns_type = None

        if columns_mapping is not None:
            self.columns = [c["map_to"] for c in columns_mapping]
            self.columns_rename = {c["name"]: c["map_to"] for c in columns_mapping}
            self.columns_type = {
                c["map_to"]: c["function"] for c in columns_mapping if c.get("type")
            }

    @abstractmethod
    def send(self, data: List[dict]) -> MaasResponse:
        """
        Sends the data to the Maas and returns a MaasResponse

        @param data: Data to send to the Service
        @return: a MaasResponse that encapsulates the returned Anomaly-Information
        """
        pass


class MlflowClient(MaasClient):
    """ Implementation of the MaasClient which uses simple mlflow (mlflow.org/)"""

    " Returns helper functions that can be used to transform the date and type returned from the maas-service"
    function_mapping = {
        "ts_to_dt": ts_to_dt,
        "unix_to_dt": unix_to_dt,
        "unixms_to_dt": unixms_to_dt,
    }

    def send(self, data: List[dict]) -> MaasResponse:

        if type(data) != list:
            raise EAException("Expected a list of dictionaries to send to the Maas.")

        pandas_df = DataFrame(data)

        # rename the columns so it aligns to the external model
        if self.columns_rename:
            pandas_df.rename(columns=self.columns_rename, inplace=True)
        # only select the specified columns
        if self.columns:
            pandas_df = pandas_df[self.columns]
        # convert the column type with a passed function
        if self.columns_type:
            for column in self.columns:
                if column in self.columns_type:
                    function = self.function_mapping.get(
                        self.columns_type[column], None
                    )
                    if function:
                        pandas_df[column] = pandas_df[column].apply(function)

        # convert to json
        json_data = pandas_df.to_json(orient="split", date_format="iso")

        headers = {"content-type": "application/json"}

        response = requests.post(self.url, data=json_data, headers=headers)
        if response.ok:
            response_list = ast.literal_eval(response.content.decode("utf-8"))
        else:
            raise EAException(
                "Error received while sending data to Maas Endpoint.\nStatus: {}\nError: {}".format(
                    response.status_code, response.content
                )
            )

        return MaasResponse.from_list(response_list)


class MaasClientMapper:
    """
    Simple Helper that returns the Client depending on the supplied item string.
    Also supports dynamic code-loading with get_module.
    """

    items = {"mlflow": MlflowClient}

    @classmethod
    def get(cls, item: str, default=MlflowClient):

        if item is None:
            return default

        mapped_item = cls.items[item] if item in cls.items else get_module(item)

        if not issubclass(mapped_item, MaasClient):
            raise EAException(
                "Mapped item {} is not of subclass of MaasClient".format(mapped_item)
            )

        return mapped_item
