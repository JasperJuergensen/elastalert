# imports
import csv
import functools
import hashlib
import logging
import warnings
from os.path import isfile as isfile

import click
import fbprophet
import mlflow
import mlflow.pyfunc
import numpy as np
import pandas as pd
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from fbprophet import Prophet
from fbprophet.diagnostics import cross_validation, performance_metrics

ES_URL = "http://192.168.122.3:9200"
ES_INDEX = "logs-endpoint-winevent-security-*"
FILTER = {"winlog.task": ":Logon"}

logging.basicConfig(level=logging.WARN)
logger = logging.getLogger(__name__)
MODEL_PARAMS = {}

conda_env = "conda_running.yaml"


class FbProphetWrapper(mlflow.pyfunc.PythonModel):
    def __init__(self, model):
        self.model = model
        super(FbProphetWrapper, self).__init__()

    def load_context(self, context):
        from fbprophet import Prophet

        return

    def predict(self, context, model_input):
        model_input["ds"] = pd.to_datetime(model_input["ds"]).dt.tz_convert(None)
        prediction = self.model.predict(model_input)
        actual = model_input["y"]

        merged = pd.concat([prediction, actual], axis=1)

        merged["outlier"] = (merged.y < merged.yhat_lower) | (
            merged.y > merged.yhat_upper
        )

        merged["anomaly_score"] = np.maximum(
            (merged.yhat - merged.y) / abs(merged.yhat_lower - merged.yhat),
            (merged.y - merged.yhat) / abs(merged.yhat_upper - merged.yhat),
        )

        merged = merged.astype({"outlier": int, "anomaly_score": float})

        return merged[["outlier", "anomaly_score"]].values.tolist()


def get_data(elast_url, index, limit=-1):
    def save_to_csv(elast_url, index, file_name):

        print("saving to csv as file did not exist")
        es = Elasticsearch(elast_url, timeout=600)
        s = Search(using=es, index=ES_INDEX)[:0]
        s = s.filter("match", **FILTER)
        s.aggs.bucket(
            "events_per_day",
            "date_histogram",
            field="@timestamp",
            calendar_interval="day",
        )
        resp = s.execute()

        with open(file_name, mode="w") as es_fd:
            writer = csv.DictWriter(es_fd, fieldnames=["ds", "y"])
            writer.writeheader()
            for hit in resp.aggregations.events_per_day:
                hit_dict = {"ds": hit.key_as_string, "y": hit.doc_count}
                writer.writerow(hit_dict)

    def read_from_csv(csv_file):

        return pd.read_csv(csv_file, parse_dates=["ds"],)

    file_name_clear = "{}{}{}".format(len(elast_url), elast_url, len(index), index)

    file_name = (
        str(hashlib.sha1(file_name_clear.encode("UTF-8")).hexdigest()[:10]) + ".csv"
    )

    print("filename: {}".format(file_name))

    if not isfile(file_name):
        save_to_csv(elast_url, index, file_name)

    data_frame = read_from_csv(file_name)

    data_frame = data_frame[:limit]

    # remove utc information as prophet cannot work with timezones
    data_frame["ds"] = data_frame["ds"].dt.tz_convert(None)

    return data_frame


def build_pipeline(data):
    m = Prophet(**MODEL_PARAMS)

    logger.warning("finished pipeline creation")
    return m


def log_output(pipe, data):
    mlflow.pyfunc.log_model(
        "model", conda_env=conda_env, python_model=FbProphetWrapper(pipe)
    )
    logger.warning("finished model logging")

    mlflow.log_param("model_param", MODEL_PARAMS)

    logger.warning("finished output logging")


def set_model_config(model_config_json):
    try:
        import json

        model_config = json.loads(model_config_json)
        MODEL_PARAMS.update(model_config)
    except:
        logger.error(
            "cannot convert model_config: {} to dict".format(model_config_json)
        )
        exit(-1)


@click.command()
@click.option("--limit-data", type=int)
@click.option("--model_config_json")
def train(limit_data, model_config_json):
    # setup logging

    logger.warning("started training")

    warnings.filterwarnings("ignore")
    np.random.seed(40)

    elast_url = ES_URL
    index = ES_INDEX

    data = get_data(elast_url, index)

    with mlflow.start_run():
        set_model_config(model_config_json)
        pipe = build_pipeline(data)
        if limit_data:
            pipe.fit(data[:limit_data])
        else:
            pipe.fit(data)

        log_output(pipe, data[:limit_data])

        return pipe


if __name__ == "__main__":
    train()
