import csv
import functools
import hashlib
import logging
import sys
import warnings
from collections import Counter
from os.path import isfile as isfile

import click
import cloudpickle
import loglizer
import mlflow
import mlflow.sklearn
import numpy as np
import pandas as pd
import sklearn
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from loglizer import preprocessing
# import sys
# sys.path.append("dependencies/loglizer")
from loglizer.models import IsolationForest, LogClustering
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer
from sklearn.svm import OneClassSVM

ES_URL = "http://192.168.122.3:9200"
ES_INDEX = "logs-endpoint-winevent-sysmon-*"
COLUMNS = ["process_path", "event_id"]
DROP_NA_COLUMNS = COLUMNS
MODEL = LogClustering
MODEL_PARAMS = {"max_dist": 0.3, "anomaly_threshold": 0.05}
LIMIT_DATA = -1

logging.basicConfig(level=logging.WARN)
logger = logging.getLogger(__name__)


conda_env = "conda_running.yaml"


def get_data(elast_url, index, columns):
    def save_to_csv(elast_url, index, columns, file_name):

        logger.warning("saving to csv as file did not exist")
        es = Elasticsearch(elast_url, timeout=600)
        s = Search(using=es, index=index).query().source(fields=columns)

        with open(file_name, mode="w") as es_fd:
            writer = csv.DictWriter(es_fd, fieldnames=columns)
            writer.writeheader()
            for hit in s.scan():

                # handles nested objects in response because of multilevel keys (i.e. agent.hostname)
                # ac
                def rgetattr(obj, attr):
                    def _getattr(obj, attr):
                        try:
                            return getattr(obj, attr)
                        except:
                            return None

                    return functools.reduce(_getattr, [obj] + attr.split("."))

                hit_dict = {column: rgetattr(hit, column) for column in columns}
                writer.writerow(hit_dict)

    def read_from_csv(csv_file):

        data = pd.read_csv(csv_file)
        return data

    file_name_clear = "{}{}{}{}{}".format(
        len(elast_url), elast_url, len(index), index, len(columns), ".".join(columns)
    )

    file_name = (
        str(hashlib.sha1(file_name_clear.encode("UTF-8")).hexdigest()[:10]) + ".csv"
    )

    logger.warning("filename: {}".format(file_name))

    if not isfile(file_name):
        save_to_csv(elast_url, index, columns, file_name)

    data_frame = read_from_csv(file_name)

    if len(DROP_NA_COLUMNS) > 0:
        data_frame.dropna(subset=DROP_NA_COLUMNS, how="any")

    logger.warning("finished reading data")

    return data_frame


def build_pipeline(data):

    pipe = Pipeline(
        steps=[
            ("numpy_transformer", FunctionTransformer(lambda x: x.to_numpy())),
            ("feature_extractor", preprocessing.FeatureExtractor()),
            ("model", MODEL(**MODEL_PARAMS)),
        ]
    )

    logger.warning("finished pipeline creation")
    return pipe


def log_output(pipe, data):

    mlflow.sklearn.log_model(pipe, "model", conda_env=conda_env)
    logger.warning("finished model logging")

    mlflow.log_param("model_param", MODEL_PARAMS)

    predictions = pipe.predict(data)
    for k, v in Counter(predictions).items():
        mlflow.log_metric("pred_{}".format(k), v)

    logger.warning("finished output logging")


def set_model_config(model, model_config_json):

    models = {"cluster": LogClustering, "iforest": IsolationForest}
    MODEL = models.get(model, LogClustering)

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
@click.option("--limit_data", type=int)
@click.option("--model")
@click.option("--model_config_json")
def train(limit_data, model, model_config_json):

    # setup logging

    logger.warning("started training")

    warnings.filterwarnings("ignore")
    np.random.seed(40)

    elast_url = ES_URL
    index = ES_INDEX

    data = get_data(elast_url, index, columns=COLUMNS)

    with mlflow.start_run():
        set_model_config(model, model_config_json)
        pipe = build_pipeline(data)
        if limit_data:
            pipe.fit(data[:limit_data])
        else:
            pipe.fit(data)

        log_output(pipe, data[:limit_data])

        return pipe


if __name__ == "__main__":
    train()
