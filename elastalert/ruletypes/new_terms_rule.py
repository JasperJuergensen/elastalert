import copy
import datetime
import logging
import sys

from elastalert.exceptions import EAException
from elastalert.queries.elasticsearch_query import (
    ElasticsearchQuery,
    ElasticsearchTermQuery,
)
from elastalert.queries.query_factory import QueryFactory
from elastalert.ruletypes import RuleType
from elastalert.utils.time import ts_now, ts_to_dt
from elastalert.utils.util import (
    add_raw_postfix,
    format_index,
    lookup_es_key,
)

log = logging.getLogger(__name__)


class NewTermsRule(RuleType):
    """ Alerts on a new value in a list of fields. """

    def init_query_factory(self):
        query_class = ElasticsearchQuery
        callback = self.add_data
        if self.rule_config.get("use_terms_query"):
            query_class = ElasticsearchTermQuery
            callback = self.add_terms_data
        return QueryFactory(query_class, self.rule_config, callback, self.es)

    def __init__(self, rule, *args, **kwargs):
        super(NewTermsRule, self).__init__(rule, *args, **kwargs)
        self.seen_values = {}
        # Allow the use of query_key or fields
        if "fields" not in self.rules:
            if "query_key" not in self.rules:
                raise EAException("fields or query_key must be specified")
            self.fields = self.rules["query_key"]
        else:
            self.fields = self.rules["fields"]
        if not self.fields:
            raise EAException("fields must not be an empty list")
        if type(self.fields) != list:
            self.fields = [self.fields]
        if self.rules.get("use_terms_query") and (
            len(self.fields) != 1
            or (len(self.fields) == 1 and type(self.fields[0]) == list)
        ):
            raise EAException(
                "use_terms_query can only be used with a single non-composite field"
            )
        if self.rules.get("use_terms_query"):
            if [self.rules["query_key"]] != self.fields:
                raise EAException(
                    "If use_terms_query is specified, you cannot specify different query_key and fields"
                )
            if not self.rules.get("query_key").endswith(
                ".keyword"
            ) and not self.rules.get("query_key").endswith(".raw"):
                if self.rules.get("use_keyword_postfix", True):
                    log.warn(
                        "Warning: If query_key is a non-keyword field, you must set "
                        "use_keyword_postfix to false, or add .keyword/.raw to your query_key."
                    )
        try:
            self.get_all_terms(args)
        except Exception as e:
            # Refuse to start if we cannot get existing terms
            raise EAException(
                "Error searching for existing terms: %s" % (repr(e))
            ).with_traceback(sys.exc_info()[2])

    def get_all_terms(self, args):
        """ Performs a terms aggregation for each field to get every existing term. """
        window_size = datetime.timedelta(
            **self.rules.get("terms_window_size", {"days": 30})
        )
        field_name = {"field": "", "size": 2147483647}  # Integer.MAX_VALUE
        query_template = {"aggs": {"values": {"terms": field_name}}}
        if args and hasattr(args, "start") and args.start:
            end = ts_to_dt(args.start)
        elif "start_date" in self.rules:
            end = ts_to_dt(self.rules["start_date"])
        else:
            end = ts_now()
        start = end - window_size
        step = datetime.timedelta(**self.rules.get("window_step_size", {"days": 1}))

        for field in self.fields:
            tmp_start = start
            tmp_end = min(start + step, end)

            time_filter = {
                self.rules["timestamp_field"]: {
                    "lt": self.rules["dt_to_ts"](tmp_end),
                    "gte": self.rules["dt_to_ts"](tmp_start),
                }
            }
            query_template["filter"] = {"bool": {"must": [{"range": time_filter}]}}
            query = {"aggs": {"filtered": query_template}}

            if "filter" in self.rules:
                for item in self.rules["filter"]:
                    query_template["filter"]["bool"]["must"].append(item)

            # For composite keys, we will need to perform sub-aggregations
            if type(field) == list:
                self.seen_values.setdefault(tuple(field), [])
                level = query_template["aggs"]
                # Iterate on each part of the composite key and add a sub aggs clause to the elastic search query
                for i, sub_field in enumerate(field):
                    if self.rules.get("use_keyword_postfix", True):
                        level["values"]["terms"]["field"] = add_raw_postfix(
                            sub_field, self.is_five_or_above()
                        )
                    else:
                        level["values"]["terms"]["field"] = sub_field
                    if i < len(field) - 1:
                        # If we have more fields after the current one, then set up the next nested structure
                        level["values"]["aggs"] = {
                            "values": {"terms": copy.deepcopy(field_name)}
                        }
                        level = level["values"]["aggs"]
            else:
                self.seen_values.setdefault(field, [])
                # For non-composite keys, only a single agg is needed
                if self.rules.get("use_keyword_postfix", True):
                    field_name["field"] = add_raw_postfix(
                        field, self.is_five_or_above()
                    )
                else:
                    field_name["field"] = field

            # Query the entire time range in small chunks
            while tmp_start < end:
                if self.rules.get("use_strftime_index"):
                    index = format_index(self.rules["index"], tmp_start, tmp_end)
                else:
                    index = self.rules["index"]
                res = self.es.search(
                    body=query, index=index, ignore_unavailable=True, timeout="50s"
                )
                if "aggregations" in res:
                    buckets = res["aggregations"]["filtered"]["values"]["buckets"]
                    if type(field) == list:
                        # For composite keys, make the lookup based on all fields
                        # Make it a tuple since it can be hashed and used in dictionary lookups
                        for bucket in buckets:
                            # We need to walk down the hierarchy and obtain the value at each level
                            self.seen_values[
                                tuple(field)
                            ] += self.flatten_aggregation_hierarchy(bucket)
                    else:
                        keys = [bucket["key"] for bucket in buckets]
                        self.seen_values[field] += keys
                else:
                    if type(field) == list:
                        self.seen_values.setdefault(tuple(field), [])
                    else:
                        self.seen_values.setdefault(field, [])
                if tmp_start == tmp_end:
                    break
                tmp_start = tmp_end
                tmp_end = min(tmp_start + step, end)
                time_filter[self.rules["timestamp_field"]] = {
                    "lt": self.rules["dt_to_ts"](tmp_end),
                    "gte": self.rules["dt_to_ts"](tmp_start),
                }

            for key, values in self.seen_values.items():
                if not values:
                    if type(key) == tuple:
                        # If we don't have any results, it could either be because of the absence of any baseline data
                        # OR it may be because the composite key contained a non-primitive type.  Either way, give the
                        # end-users a heads up to help them debug what might be going on.
                        log.warning(
                            (
                                "No results were found from all sub-aggregations.  This can either indicate that there is "
                                "no baseline data OR that a non-primitive field was used in a composite key."
                            )
                        )
                    else:
                        log.info("Found no values for %s" % (field))
                    continue
                self.seen_values[key] = list(set(values))
                log.info("Found %s unique values for %s" % (len(set(values)), key))

    def flatten_aggregation_hierarchy(self, root, hierarchy_tuple=()):
        """ For nested aggregations, the results come back in the following format:
            {
            "aggregations" : {
                "filtered" : {
                  "doc_count" : 37,
                  "values" : {
                    "doc_count_error_upper_bound" : 0,
                    "sum_other_doc_count" : 0,
                    "buckets" : [ {
                      "key" : "1.1.1.1", # IP address (root)
                      "doc_count" : 13,
                      "values" : {
                        "doc_count_error_upper_bound" : 0,
                        "sum_other_doc_count" : 0,
                        "buckets" : [ {
                          "key" : "80",    # Port (sub-aggregation)
                          "doc_count" : 3,
                          "values" : {
                            "doc_count_error_upper_bound" : 0,
                            "sum_other_doc_count" : 0,
                            "buckets" : [ {
                              "key" : "ack",  # Reason (sub-aggregation, leaf-node)
                              "doc_count" : 3
                            }, {
                              "key" : "syn",  # Reason (sub-aggregation, leaf-node)
                              "doc_count" : 1
                            } ]
                          }
                        }, {
                          "key" : "82",    # Port (sub-aggregation)
                          "doc_count" : 3,
                          "values" : {
                            "doc_count_error_upper_bound" : 0,
                            "sum_other_doc_count" : 0,
                            "buckets" : [ {
                              "key" : "ack",  # Reason (sub-aggregation, leaf-node)
                              "doc_count" : 3
                            }, {
                              "key" : "syn",  # Reason (sub-aggregation, leaf-node)
                              "doc_count" : 3
                            } ]
                          }
                        } ]
                      }
                    }, {
                      "key" : "2.2.2.2", # IP address (root)
                      "doc_count" : 4,
                      "values" : {
                        "doc_count_error_upper_bound" : 0,
                        "sum_other_doc_count" : 0,
                        "buckets" : [ {
                          "key" : "443",    # Port (sub-aggregation)
                          "doc_count" : 3,
                          "values" : {
                            "doc_count_error_upper_bound" : 0,
                            "sum_other_doc_count" : 0,
                            "buckets" : [ {
                              "key" : "ack",  # Reason (sub-aggregation, leaf-node)
                              "doc_count" : 3
                            }, {
                              "key" : "syn",  # Reason (sub-aggregation, leaf-node)
                              "doc_count" : 3
                            } ]
                          }
                        } ]
                      }
                    } ]
                  }
                }
              }
            }

            Each level will either have more values and buckets, or it will be a leaf node
            We'll ultimately return a flattened list with the hierarchies appended as strings,
            e.g the above snippet would yield a list with:

            [
             ('1.1.1.1', '80', 'ack'),
             ('1.1.1.1', '80', 'syn'),
             ('1.1.1.1', '82', 'ack'),
             ('1.1.1.1', '82', 'syn'),
             ('2.2.2.2', '443', 'ack'),
             ('2.2.2.2', '443', 'syn')
            ]

            A similar formatting will be performed in the add_data method and used as the basis for comparison

        """
        results = []
        # There are more aggregation hierarchies left.  Traverse them.
        if "values" in root:
            results += self.flatten_aggregation_hierarchy(
                root["values"]["buckets"], hierarchy_tuple + (root["key"],)
            )
        else:
            # We've gotten to a sub-aggregation, which may have further sub-aggregations
            # See if we need to traverse further
            for node in root:
                if "values" in node:
                    results += self.flatten_aggregation_hierarchy(node, hierarchy_tuple)
                else:
                    results.append(hierarchy_tuple + (node["key"],))
        return results

    def add_data(self, data):
        for document in data:
            for field in self.fields:
                value = ()
                lookup_field = field
                if type(field) == list:
                    # For composite keys, make the lookup based on all fields
                    # Make it a tuple since it can be hashed and used in dictionary lookups
                    lookup_field = tuple(field)
                    for sub_field in field:
                        lookup_result = lookup_es_key(document, sub_field)
                        if not lookup_result:
                            value = None
                            break
                        value += (lookup_result,)
                else:
                    value = lookup_es_key(document, field)
                if not value and self.rules.get("alert_on_missing_field"):
                    document["missing_field"] = lookup_field
                    self.add_match(copy.deepcopy(document))
                elif value:
                    if value not in self.seen_values[lookup_field]:
                        document["new_field"] = lookup_field
                        self.add_match(copy.deepcopy(document))
                        self.seen_values[lookup_field].append(value)

    def add_terms_data(self, terms):
        # With terms query, len(self.fields) is always 1 and the 0'th entry is always a string
        field = self.fields[0]
        for timestamp, buckets in terms.items():
            for bucket in buckets:
                if bucket["doc_count"]:
                    if bucket["key"] not in self.seen_values[field]:
                        match = {
                            field: bucket["key"],
                            self.rules["timestamp_field"]: timestamp,
                            "new_field": field,
                        }
                        self.add_match(match)
                        self.seen_values[field].append(bucket["key"])

    def is_five_or_above(self):
        version = self.es.info()["version"]["number"]
        return int(version[0]) >= 5
