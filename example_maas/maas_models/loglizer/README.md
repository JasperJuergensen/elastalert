# Loglizer

Uses the Loglizer library (https://github.com/logpai/loglizer) to predict anomalies.

## Dependency

The loglizer library cannot be downloaded with pip yet, because it was not released on the repositories. Also a few fixes were necessary to make it fully compliant with sklearn. Thus currently it is mantained as a loose dependency in the dependencies folder. The dependencies are based on (https://github.com/logpai/loglizer).

## Adapt for usage

In order to use the loglizer dependency, the path to the dependency must be defined in the conda_running.yaml file.


## Parameters

* limit-data: (Default: None), Possible Values: Integers, Description: Limits the selected data from elasticsearch to the provided amount of rows. Limits may be necessary to decrease the time for the model generation phase, as only the limited-data is used to generate the model.
* model: (Default: cluster), Possible Values: "cluster", "iforest", Description: Selects the model as a cluster model or isolationforest model to predict anomalies.
* model_config_json: (Default: {}) Supply configurations for the model as a json string. Check the configuration options for loglizer for more information on possible configuration values.
