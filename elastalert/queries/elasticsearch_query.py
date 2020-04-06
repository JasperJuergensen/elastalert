import copy
import logging
from typing import List, Union

from elastalert import config
from elastalert.exceptions import EARuntimeException
from elastalert.queries import BaseQuery
from elastalert.utils.time import dt_to_ts, pretty_ts, ts_now
from elastalert.utils.util import (
    elasticsearch_client,
    get_index_start,
    lookup_es_key,
    set_es_key,
    should_scrolling_continue,
)
from elasticsearch import ElasticsearchException, NotFoundError

log = logging.getLogger(__name__)


class ElasticsearchQuery(BaseQuery):
    """"""

    def __init__(self, rule_config: dict, callback: callable, persistent: dict):
        super().__init__(rule_config, callback, persistent)
        self.scroll_id = None
        self.total_hits = 0
        self.num_hits = 0
        self.num_dupes = 0
        self.persistent.setdefault("processed_hits", {})
        self.es = elasticsearch_client(config.get_config())

    def build_query(self, sort: bool = True):
        self.query = {"query": {"bool": {"filter": self.rule_config.get("filter", [])}}}
        if sort:
            self.query["sort"] = [self.rule_config.get("timestamp_field", "@timestamp")]

    def get_hits(self, starttime: str, endtime: str) -> List[dict]:
        if starttime and endtime:
            self.query["query"]["bool"].update(
                {
                    "must": {
                        "range": {
                            self.rule_config.get("timestamp_field", "@timestamp"): {
                                "gt": starttime,
                                "lte": endtime,
                            }
                        }
                    }
                }
            )
        extra_args = {"_source_includes": self.rule_config["include"]}
        scroll_keepalive = self.rule_config.get(
            "scroll_keepalive", config.get_config().get("scroll_keepalive", "30s")
        )
        try:
            log.debug("Running query: %s", self.query)
            if self.scroll_id:
                res = self.es.scroll(scroll_id=self.scroll_id, scroll=scroll_keepalive)
            else:
                res = self.es.search(
                    scroll=scroll_keepalive,
                    index=self.rule_config["index"],
                    size=self.rule_config.get(
                        "max_query_size",
                        config.get_config().get("max_query_size", 10000),
                    ),
                    body=self.query,
                    ignore_unavailable=True,
                    **extra_args
                )
                self.total_hits = int(res["hits"]["total"]["value"])
        except ElasticsearchException as e:
            # Elasticsearch sometimes gives us GIGANTIC error messages
            # (so big that they will fill the entire terminal buffer)
            if len(str(e)) > 1024:
                msg = str(e)[:1024] + "... (%d characters removed)" % (
                    len(str(e)) - 1024
                )
            else:
                msg = str(e)
            raise EARuntimeException(
                "Error running query %s" % msg,
                rule=self.rule_config["name"],
                query=self.query,
            )

        if "_scroll_id" in res:
            # The scroll_id can change after every request (scroll and search)
            self.scroll_id = res["_scroll_id"]

        if len(res.get("_shards", {}).get("failures", [])) > 0:
            try:
                errs = [
                    e["reason"]["reason"]
                    for e in res["_shards"]["failures"]
                    if "Failed to parse" in e["reason"]["reason"]
                ]
                if len(errs):
                    raise EARuntimeException(
                        "\n".join(errs), rule=self.rule_config["name"], query=self.query
                    )
            except (TypeError, KeyError) as e:
                raise EARuntimeException(
                    str(res["_shards"]["failures"]),
                    rule=self.rule_config["name"],
                    query=self.query,
                    original_exception=e,
                )

        hits = res["hits"]["hits"]
        self.num_hits += len(hits)
        lt = self.rule_config.get("use_local_time")
        log.info(
            "Queried rule %s on %s from %s to %s: %s / %s hits (scrolling %s from )",
            self.rule_config["name"],
            self.rule_config["index"],
            pretty_ts(starttime, lt),
            pretty_ts(endtime, lt),
            len(hits),
            self.num_hits,
            self.total_hits,
        )

        return self.process_hits(self.rule_config, hits)

    def run_query(self, starttime=None, endtime=None) -> int:
        if starttime is None:
            starttime = get_index_start(self.rule_config["index"])
        if endtime is None:
            endtime = ts_now()
        starttime = self.rule_config.get("dt_to_ts", dt_to_ts)(starttime)
        endtime = self.rule_config.get("dt_to_ts", dt_to_ts)(endtime)
        data = self.get_hits(starttime, endtime)
        if data:
            old_len = len(data)
            data = self.remove_duplicates(data)
            self.num_dupes += old_len - len(data)
            self.callback(data)
        try:
            if (
                self.scroll_id
                and self.num_hits < self.total_hits
                and should_scrolling_continue(self.rule_config)
            ):
                self.run_query(starttime, endtime)
        except RuntimeError:
            # It's possible to scroll far enough to hit max recursive depth
            log.warning("Scrolling hit maximum recursion depth.")
        if self.scroll_id:
            try:
                self.es.clear_scroll(scroll_id=self.scroll_id)
            except NotFoundError:
                pass
        return self.num_hits

    def remove_duplicates(self, data: List[dict]) -> List[dict]:
        new_events = []
        for event in data:
            if event["_id"] in self.persistent["processed_hits"]:
                continue

            # Remember the new data's IDs
            self.persistent["processed_hits"][event["_id"]] = lookup_es_key(
                event, self.rule_config.get("timestamp_field", "@timestamp")
            )
            new_events.append(event)

        return new_events

    @staticmethod
    def process_hits(rule_config: dict, hits) -> List[dict]:
        """
        Update the _source field for each hit received from ES based on the rule configuration.

        This replaces timestamps with datetime objects,
        folds important fields into _source and creates compound query_keys.

        :return: A list of processed _source dictionaries.
        """

        processed_hits = []
        for hit in hits:
            # Merge fields and _source
            hit.setdefault("_source", {})
            for key, value in list(hit.get("fields", {}).items()):
                # Fields are returned as lists, assume any with length 1 are not arrays in _source
                # Except sometimes they aren't lists. This is dependent on ES version
                hit["_source"].setdefault(
                    key, value[0] if type(value) is list and len(value) == 1 else value
                )

            # Convert the timestamp to a datetime
            ts = lookup_es_key(hit["_source"], rule_config["timestamp_field"])
            if not ts and not rule_config["_source_enabled"]:
                raise EARuntimeException(
                    "Error: No timestamp was found for hit. '_source_enabled' is set to false, check your mappings for stored fields"
                )

            set_es_key(
                hit["_source"],
                rule_config["timestamp_field"],
                rule_config["ts_to_dt"](ts),
            )
            set_es_key(
                hit,
                rule_config["timestamp_field"],
                lookup_es_key(hit["_source"], rule_config["timestamp_field"]),
            )

            # Tack metadata fields into _source
            for field in ["_id", "_index", "_type"]:
                if field in hit:
                    hit["_source"][field] = hit[field]

            if rule_config.get("compound_query_key"):
                values = [
                    lookup_es_key(hit["_source"], key)
                    for key in rule_config["compound_query_key"]
                ]
                hit["_source"][rule_config["query_key"]] = ", ".join(
                    [str(value) for value in values]
                )

            if rule_config.get("compound_aggregation_key"):
                values = [
                    lookup_es_key(hit["_source"], key)
                    for key in rule_config["compound_aggregation_key"]
                ]
                hit["_source"][rule_config["aggregation_key"]] = ", ".join(
                    [str(value) for value in values]
                )

            processed_hits.append(hit["_source"])

        return processed_hits


class ElasticsearchCountQuery(ElasticsearchQuery):
    def get_hits(self, starttime: str, endtime: str) -> Union[dict, None]:
        query = copy.deepcopy(self.query)
        if starttime and endtime:
            self.query["query"]["bool"].update(
                {
                    "must": {
                        "range": {
                            self.rule_config.get("timestamp_field", "@timestamp"): {
                                "gt": starttime,
                                "lte": endtime,
                            }
                        }
                    }
                }
            )
        try:
            log.debug("Running query: %s", self.query)
            res = self.es.count(
                index=self.rule_config["index"],
                body=self.query,
                ignore_unaivailable=True,
            )
        except ElasticsearchException as e:
            # Elasticsearch sometimes gives us GIGANTIC error messages
            # (so big that they will fill the entire terminal buffer)
            if len(str(e)) > 1024:
                msg = str(e)[:1024] + "... (%d characters removed)" % (
                    len(str(e)) - 1024
                )
            else:
                msg = str(e)
            raise EARuntimeException(
                "Error running terms query %s" % msg,
                rule=self.rule_config["name"],
                query=query,
                original_exception=e,
            )
        self.num_hits += res["count"]
        lt = self.rule_config.get("use_local_time")
        log.info(
            "Queried rule %s from %s to %s: %s buckets",
            self.rule_config["name"],
            pretty_ts(starttime, lt),
            pretty_ts(endtime, lt),
            res["count"],
        )
        return {endtime: res["count"]}


class ElasticsearchTermQuery(ElasticsearchQuery):
    def build_query(self, **kwargs):
        super().build_query(False)
        self.query["query"].update(
            {
                "aggs": {
                    "counts": {
                        "terms": {
                            "field": self.rule_config["query_key"],
                            "size": self.rule_config.get("terms_size", 50),
                            "min_doc_count": self.rule_config.get("min_doc_count", 1),
                        }
                    }
                }
            }
        )

    def get_hits(self, starttime: str, endtime: str) -> Union[dict, None]:
        if starttime and endtime:
            self.query["query"]["bool"].update(
                {
                    "must": {
                        "range": {
                            self.rule_config.get("timestamp_field", "@timestamp"): {
                                "gt": starttime,
                                "lte": endtime,
                            }
                        }
                    }
                }
            )
        try:
            log.debug("Running query: %s", self.query)
            res = self.es.search(
                index=self.rule_config["index"],
                body=self.query,
                ignore_unavailable=True,
            )
        except ElasticsearchException as e:
            # Elasticsearch sometimes gives us GIGANTIC error messages
            # (so big that they will fill the entire terminal buffer)
            if len(str(e)) > 1024:
                msg = str(e)[:1024] + "... (%d characters removed)" % (
                    len(str(e)) - 1024
                )
            else:
                msg = str(e)
            raise EARuntimeException(
                "Error running terms query %s" % msg,
                rule=self.rule_config["name"],
                query=self.query,
                original_exception=e,
            )

        if "aggregations" not in res:
            log.info("Missing aggregations result: %s", res)
            return None

        buckets = res["aggregations"]["counts"]["buckets"]
        self.num_hits += len(buckets)
        lt = self.rule_config.get("use_local_time")
        log.info(
            "Queried rule %s from %s to %s: %s buckets",
            self.rule_config["name"],
            pretty_ts(starttime, lt),
            pretty_ts(endtime, lt),
            len(buckets),
        )
        return {endtime: buckets}

    def remove_duplicates(self, data: List[dict]) -> List[dict]:
        return data


class ElasticsearchAggregationQuery(ElasticsearchQuery):
    def build_query(self, **kwargs):
        super().build_query(False)
        bucket_interval_period = self.rule_config.get("bucket_interval_period")
        if bucket_interval_period:
            aggs_element = {
                "interval_aggs": {
                    "date_histogram": {
                        "field": self.rule_config.get("timestamp_field", "@timestamp"),
                        "fixed_interval": bucket_interval_period,
                    },
                    "aggs": self.rule_config["aggregation_query_element"],
                }
            }
            if self.rule_config.get("bucket_offset_delta"):
                aggs_element["interval_aggs"]["date_histogram"][
                    "offset"
                ] = "+{}s".format(self.rule_config["bucket_offset_delta"])
        else:
            aggs_element = self.rule_config["aggregation_query_element"]

        if self.rule_config.get("query_key"):
            for idx, key in reversed(
                list(enumerate(self.rule_config["query_key"].split(",")))
            ):
                aggs_element = {
                    "bucket_aggs": {
                        "terms": {
                            "field": key,
                            "size": self.rule_config.get("terms_size", 50),
                            "min_doc_count": self.rule_config.get("min_doc_count", 1),
                        },
                        "aggs": aggs_element,
                    }
                }
        self.query.update({"aggs": aggs_element})

    def get_hits(self, starttime: str, endtime: str) -> Union[dict, None]:
        if starttime and endtime:
            self.query["query"]["bool"].update(
                {
                    "must": {
                        "range": {
                            self.rule_config.get("timestamp_field", "@timestamp"): {
                                "gt": starttime,
                                "lte": endtime,
                            }
                        }
                    }
                }
            )
        try:
            log.debug("Running query: %s", self.query)
            res = self.es.search(
                index=self.rule_config["index"],
                body=self.query,
                ignore_unavailable=True,
            )
        except ElasticsearchException as e:
            # Elasticsearch sometimes gives us GIGANTIC error messages
            # (so big that they will fill the entire terminal buffer)
            if len(str(e)) > 1024:
                msg = str(e)[:1024] + "... (%d characters removed)" % (
                    len(str(e)) - 1024
                )
            else:
                msg = str(e)
            raise EARuntimeException(
                "Error running terms query %s" % msg,
                rule=self.rule_config["name"],
                query=self.query,
                original_exception=e,
            )
        if "aggregations" not in res:
            log.info("Missing aggregations result: %s", res)
            return None
        payload = res["aggregations"]

        self.num_hits += res["hits"]["total"]["value"]

        return {endtime: payload}
