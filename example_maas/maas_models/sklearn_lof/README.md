# SKLEARN-LOF

Uses Local-Outlier-Factor of sklearn to determine anomalies.

## Parameters

* limit-data: (Default: None), Possible Values: Integers, Description: Limits the selected data from elasticsearch to the provided amount of rows. Limits may be necessary to decrease the time for the model generation phase, as only the limited-data is used to generate the model.
* model_config_json: (Default: {}) Supply configurations for the model as a json string. Check the configuration options for sklearn_lof for more information on possible configuration values.
