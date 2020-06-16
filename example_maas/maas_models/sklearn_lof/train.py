import csv
import functools
import hashlib
import logging
import sys
import warnings
from collections import Counter
from os.path import isfile as isfile

import click
import mlflow
import mlflow.sklearn
import numpy as np
import pandas as pd
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.svm import OneClassSVM

ES_URL = "http://192.168.122.3:9200"
ES_INDEX = "logs-endpoint-winevent-sysmon-*"
COLUMNS = ["process_path", "event_id"]
DROP_NA_COLUMNS = COLUMNS
MODEL = LocalOutlierFactor
MODEL_PARAMS = {"novelty": True}


logging.basicConfig(level=logging.WARN)
logger = logging.getLogger(__name__)


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

    logger.warning(
        "filename: {}, filename_clear: {}".format(file_name, file_name_clear)
    )

    if not isfile(file_name):
        save_to_csv(elast_url, index, columns, file_name)

    data_frame = read_from_csv(file_name)

    if len(DROP_NA_COLUMNS) > 0:
        data_frame.dropna(subset=DROP_NA_COLUMNS, how="any")

    logger.warning("finished reading data")

    return data_frame


def build_pipeline(data, *params):
    np.random.seed(40)

    numeric_transformer = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ]
    )

    numeric_features = data.select_dtypes(include=["int64", "float64"]).columns

    categorical_transformer = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="constant", fill_value="missing")),
            ("onehot", OneHotEncoder(handle_unknown="ignore")),
        ]
    )

    categorical_features = data.select_dtypes(include=["object"]).columns

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", numeric_transformer, numeric_features),
            ("cat", categorical_transformer, categorical_features),
        ]
    )

    # create Model
    o_svm = MODEL(**MODEL_PARAMS)

    # create pipeline
    pipe = Pipeline([("preprocessor", preprocessor), ("svc", o_svm)])

    logger.warning("finished pipeline creation")
    return pipe


def log_output(pipe, data):

    mlflow.sklearn.log_model(pipe, "model")
    logger.warning("finished model logging")

    params = pipe.steps[-1][1].get_params()
    mlflow.log_param("model_param", params)

    predictions = pipe.predict(data)
    for k, v in Counter(predictions).items():
        mlflow.log_metric("pred_{}".format(k), v)

    logger.warning("finished output logging")


@click.command()
@click.option("--limit_data", type=int, required=True)
@click.option("--model_config_json", required=True)
def train(limit_data, model_config_json):

    np.random.seed(40)

    logger.warning("started training")

    set_model_config(model_config_json)
    logger.warning("configured model parameters")

    elast_url = ES_URL
    index = ES_INDEX
    data = get_data(elast_url, index, columns=COLUMNS)

    with mlflow.start_run():
        pipe = build_pipeline(data)
        pipe.fit(data[:limit_data])

        log_output(pipe, data)

        return pipe


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


if __name__ == "__main__":
    train()
