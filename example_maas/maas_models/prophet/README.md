# Prophet

Uses the facebook-prophet library (https://facebook.github.io/prophet/docs/quick_start.html) to predict time anomalies.

## Parameters

* limit-data: (Default: None), Possible Values: Integers, Description: Limits the selected data from elasticsearch to the provided amount of rows. Limits may be necessary to decrease the time for the model generation phase, as only the limited-data is used to generate the model.
* model_config_json: (Default: {}) Supply configurations for the model as a json string. Check the configuration options for prophet for more information on possible configuration values.
