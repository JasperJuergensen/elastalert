import collections
import datetime
import logging
import os
import re
import sys
from typing import Callable

import pytz
from elastalert import config
from elastalert.clients import ElasticSearchClient
from elastalert.exceptions import EAException, EARuntimeException
from elastalert.utils.time import (
    dt_to_unix,
    total_seconds,
    ts_now,
    ts_to_dt,
    unix_to_dt,
)
from elasticsearch import ElasticsearchException
from six import string_types

log = logging.getLogger(__name__)


def get_module(module_name: str):
    """ Loads a module and returns a specific object.
    module_name should 'module.file.object'.
    Returns object or raises EAException on error. """
    sys.path.append(os.getcwd())
    try:
        module_path, module_class = module_name.rsplit(".", 1)
        base_module = __import__(module_path, globals(), locals(), [module_class])
        module = getattr(base_module, module_class)
    except (ImportError, AttributeError, ValueError) as e:
        raise EAException(
            "Could not import module %s: %s" % (module_name, e)
        ).with_traceback(sys.exc_info()[2])
    return module


def new_get_event_ts(ts_field) -> Callable:
    """ Constructs a lambda that may be called to extract the timestamp field
    from a given event.

    :returns: A callable function that takes an event and outputs that event's
    timestamp field.
    """
    return lambda event: lookup_es_key(event[0], ts_field)


def _find_es_dict_by_key(lookup_dict, term):
    """ Performs iterative dictionary search based upon the following conditions:

    1. Subkeys may either appear behind a full stop (.) or at one lookup_dict level lower in the tree.
    2. No wildcards exist within the provided ES search terms (these are treated as string literals)

    This is necessary to get around inconsistencies in ES data.

    For example:
      {'ad.account_name': 'bob'}
    Or:
      {'csp_report': {'blocked_uri': 'bob.com'}}
    And even:
       {'juniper_duo.geoip': {'country_name': 'Democratic People's Republic of Korea'}}

    We want a search term of form "key.subkey.subsubkey" to match in all cases.
    :returns: A tuple with the first element being the dict that contains the key and the second
    element which is the last subkey used to access the target specified by the term. None is
    returned for both if the key can not be found.
    """
    if term in lookup_dict:
        return lookup_dict, term
    # If the term does not match immediately, perform iterative lookup:
    # 1. Split the search term into tokens
    # 2. Recurrently concatenate these together to traverse deeper into the dictionary,
    #    clearing the subkey at every successful lookup.
    #
    # This greedy approach is correct because subkeys must always appear in order,
    # preferring full stops and traversal interchangeably.
    #
    # Subkeys will NEVER be duplicated between an alias and a traversal.
    #
    # For example:
    #  {'foo.bar': {'bar': 'ray'}} to look up foo.bar will return {'bar': 'ray'}, not 'ray'
    dict_cursor = lookup_dict

    subkey = ""
    while term:
        split_results = re.split(r"\[(\d)\]", term, maxsplit=1)
        if len(split_results) == 3:
            sub_term, index, term = split_results
            index = int(index)
        else:
            sub_term, index, term = split_results + [None, ""]

        subkeys = sub_term.split(".")

        while len(subkeys) > 0:
            if not dict_cursor:
                return {}, None

            subkey += subkeys.pop(0)

            if subkey in dict_cursor:
                if len(subkeys) == 0:
                    break
                dict_cursor = dict_cursor[subkey]
                subkey = ""
            elif len(subkeys) == 0:
                # If there are no keys left to match, return None values
                dict_cursor = None
                subkey = None
            else:
                subkey += "."

        if index is not None and subkey:
            dict_cursor = dict_cursor[subkey]
            if type(dict_cursor) == list and len(dict_cursor) > index:
                subkey = index
                if term:
                    dict_cursor = dict_cursor[subkey]
            else:
                return {}, None

    return dict_cursor, subkey


def set_es_key(lookup_dict, term, value):
    """ Looks up the location that the term maps to and sets it to the given value.
    :returns: True if the value was set successfully, False otherwise.
    """
    value_dict, value_key = _find_es_dict_by_key(lookup_dict, term)

    if value_dict is not None:
        value_dict[value_key] = value
        return True

    return False


def lookup_es_key(lookup_dict, term):
    """ Performs iterative dictionary search for the given term.
    :returns: The value identified by term or None if it cannot be found.
    """
    value_dict, value_key = _find_es_dict_by_key(lookup_dict, term)
    return None if value_key is None else value_dict[value_key]


def hashable(obj):
    """ Convert obj to a hashable obj.
    We use the value of some fields from Elasticsearch as keys for dictionaries. This means
    that whatever Elasticsearch returns must be hashable, and it sometimes returns a list or dict."""
    if not obj.__hash__:
        return str(obj)
    return obj


def format_index(index, start, end, add_extra=False):
    """ Takes an index, specified using strftime format, start and end time timestamps,
    and outputs a wildcard based index string to match all possible timestamps. """
    # Convert to UTC
    start -= start.utcoffset()
    end -= end.utcoffset()
    original_start = start
    indices = set()
    while start.date() <= end.date():
        indices.add(start.strftime(index))
        start += datetime.timedelta(days=1)
    if add_extra:
        num = len(indices)
        while len(indices) == num:
            original_start -= datetime.timedelta(days=1)
            new_index = original_start.strftime(index)
            if new_index == index:
                raise EAException(
                    "You cannot use a static index with search_extra_index"
                )
            indices.add(new_index)

    return ",".join(indices)


def add_raw_postfix(field, is_five_or_above):
    end = ".keyword" if is_five_or_above else ".raw"
    if not field.endswith(end):
        field += end
    return field


def replace_dots_in_field_names(document):
    """ This method destructively modifies document by replacing any dots in
    field names with an underscore. """
    for key, value in list(document.items()):
        if isinstance(value, dict):
            value = replace_dots_in_field_names(value)
        if isinstance(key, string_types) and key.find(".") != -1:
            del document[key]
            document[key.replace(".", "_")] = value
    return document


def elasticsearch_client(conf: config.ESClient) -> ElasticSearchClient:
    """ returns an :class:`ElasticSearchClient` instance configured using an es_conn_config """
    return ElasticSearchClient(conf)


def pytzfy(dt):
    # apscheduler requires pytz timezone objects
    # This function will replace a dateutil.tz one with a pytz one
    if dt.tzinfo is not None:
        new_tz = pytz.timezone(dt.tzinfo.tzname("Y is this even required??"))
        return dt.replace(tzinfo=new_tz)
    return dt


def parse_duration(value):
    """Convert ``unit=num`` spec into a ``timedelta`` object."""
    unit, num = value.split("=")
    return datetime.timedelta(**{unit: int(num)})


def parse_deadline(value):
    """Convert ``unit=num`` spec into a ``datetime`` object."""
    duration = parse_duration(value)
    return ts_now() + duration


def flatten_dict(dct, delim=".", prefix=""):
    ret = {}
    for key, val in list(dct.items()):
        if type(val) == dict:
            ret.update(flatten_dict(val, prefix=prefix + key + delim))
        else:
            ret[prefix + key] = val
    return ret


def resolve_string(string, match, missing_text="<MISSING VALUE>"):
    """
        Given a python string that may contain references to fields on the match dictionary,
            the strings are replaced using the corresponding values.
        However, if the referenced field is not found on the dictionary,
            it is replaced by a default string.
        Strings can be formatted using the old-style format ('%(field)s') or
            the new-style format ('{match[field]}').

        :param string: A string that may contain references to values of the 'match' dictionary.
        :param match: A dictionary with the values to replace where referenced by keys in the string.
        :param missing_text: The default text to replace a formatter with if the field doesnt exist.
    """
    flat_match = flatten_dict(match)
    flat_match.update(match)
    dd_match = collections.defaultdict(lambda: missing_text, flat_match)
    dd_match["_missing_value"] = missing_text
    while True:
        try:
            string = string % dd_match
            string = string.format(**dd_match)
            break
        except KeyError as e:
            if "{%s}" % str(e).strip("'") not in string:
                break
            string = string.replace("{%s}" % str(e).strip("'"), "{_missing_value}")

    return string


def should_scrolling_continue(rule_conf):
    """
    Tells about a rule config if it can scroll still or should stop the scrolling.

    :param: rule_conf as dict
    :rtype: bool
    """
    max_scrolling = rule_conf.get("max_scrolling_count")
    stop_the_scroll = 0 < max_scrolling <= rule_conf.get("scrolling_cycle")

    return not stop_the_scroll


def get_starttime(rule_config: dict) -> datetime:
    """ Query ES for the last time we ran this rule.

    :param rule_config: The rule configuration.
    :return: A timestamp or None.
    """
    query = {
        "query": {"bool": {"filter": {"term": {"rule_name": rule_config["name"]}}}},
        "sort": {"@timestamp": {"order": "desc"}},
    }

    try:
        writeback_es = elasticsearch_client(
            config.CFG().es_client
        )  # TODO this should use the es config from the rule
        doc_type = "elastalert_status"
        index = writeback_es.resolve_writeback_index(
            config.CFG().writeback_index, doc_type
        )
        res = writeback_es.search(
            index=index, size=1, body=query, _source_includes=["endtime", "rule_name"]
        )
        if res["hits"]["hits"]:
            endtime = ts_to_dt(res["hits"]["hits"][0]["_source"]["endtime"])

            if ts_now() - endtime < config.CFG().old_query_limit:
                return endtime
            else:
                log.info(
                    "Found expired previous run for %s at %s"
                    % (rule_config["name"], endtime)
                )
                return None
    except (ElasticsearchException, KeyError) as e:
        raise EARuntimeException(
            "Error querying for last run: %s" % e,
            rule=rule_config["name"],
            original_exception=e,
        )


def get_index_start(index: str, timestamp_field: str = "@timestamp") -> str:
    """ Query for one result sorted by timestamp to find the beginning of the index.

    :param index: The index of which to find the earliest event.
    :param timestamp_field: The name of the timestamp field
    :return: Timestamp of the earliest event.
    """
    query = {"sort": {timestamp_field: {"order": "asc"}}}
    try:
        es = elasticsearch_client(config.CFG().es_client)
        res = es.search(
            index=index,
            size=1,
            body=query,
            _source_includes=[timestamp_field],
            ignore_unavailable=True,
        )
    except ElasticsearchException as e:
        raise EARuntimeException(
            "Elasticsearch query error: %s" % e, query=query, original_exception=e
        )
    if len(res["hits"]["hits"]) == 0:
        # Index is completely empty, return a date before the epoch
        return "1969-12-30T00:00:00Z"
    return res["hits"]["hits"][0][timestamp_field]


def get_index(rule, starttime=None, endtime=None):
    """ Gets the index for a rule. If strftime is set and starttime and endtime
    are provided, it will return a comma seperated list of indices. If strftime
    is set but starttime and endtime are not provided, it will replace all format
    tokens with a wildcard. """
    index = rule["index"]
    add_extra = rule.get("search_extra_index", False)
    if rule.get("use_strftime_index"):
        if starttime and endtime:
            return format_index(index, starttime, endtime, add_extra)
        else:
            # Replace the substring containing format characters with a *
            format_start = index.find("%")
            format_end = index.rfind("%") + 2
            return index[:format_start] + "*" + index[format_end:]
    else:
        return index


def enhance_filter(rule):
    """ If there is a blacklist or whitelist in rule then we add it to the filter.
    It adds it as a query_string. If there is already an query string its is appended
    with blacklist or whitelist.

    :param rule:
    :return:
    """
    if not rule.get("filter_by_list", True):
        return
    if "blacklist" in rule:
        listname = "blacklist"
    elif "whitelist" in rule:
        listname = "whitelist"
    else:
        return

    filters = rule["filter"]
    additional_terms = []
    for term in rule[listname]:
        if not (term.startswith("/") and term.endswith("/")):
            additional_terms.append(rule["compare_key"] + ':"' + term + '"')
        else:
            # These are regular expressions and won't work if they are quoted
            additional_terms.append(rule["compare_key"] + ":" + term)
    if listname == "whitelist":
        query = "NOT " + " AND NOT ".join(additional_terms)
    else:
        query = " OR ".join(additional_terms)
    query_str_filter = {"query_string": {"query": query}}
    filters.append(query_str_filter)
    log.debug(
        "Enhanced filter with {} terms: {}".format(listname, str(query_str_filter))
    )
