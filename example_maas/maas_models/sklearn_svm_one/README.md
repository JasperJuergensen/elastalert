# SKLEARN_SVM_ONE

Uses the Oneclass-SVM of sklearn to determine anomalies.

## Parameters

* limit-data: (Default: None), Possible Values: Integers, Description: Limits the selected data from elasticsearch to the provided amount of rows. Limits may be necessary to decrease the time for the model generation phase, as only the limited-data is used to generate the model.
