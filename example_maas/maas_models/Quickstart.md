# Preface

This models require sysmon data (see the HELK project https://github.com/Cyb3rWard0g/HELK) in the index
logs-endpoint-winevent-sysmon-*.

The models are not configured to find real anomalies as they are not adapted on the data. They only serve the purpose of showing on how to use different libraries with the elastalert maas and maas_aggregation rule and can be used as building blocks for real models.

# Usage

## Mlflow install

Use at least python 3.6 for the mlflow.

`````
pip install mlflow
`````


## Mlflow modify model

Modify the following parameters:

- ES_URL: Point to you elasticsearch install

## Mlflow run model

Run the following command in the current folder to generate artifcats and mlflow run results. The artifcats are later on used for serving the prediction model

`````
mlflow run [model_name/folder]
`````

Executing the command returns a run_id, which can be used to serve the model. If errors occur, check if a README was supplied by the model and additional manual steps are necessary. Additional parameters can be provided with -P value=key for each parameters. To find out which parameters are available check the README.md file of the used model.

## Mlflow serve model

Run the following command to serve the model

`````
mlflow models serve -m runs:/[run-id]/model -p [port]
`````

This creates an socket on the supplied port with the default endpoint http://localhost:[port]/invocations, which returns the predictions on supplied data.
