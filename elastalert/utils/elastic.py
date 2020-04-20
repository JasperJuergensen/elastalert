from elastalert.utils.util import lookup_es_key


def get_query_key_value(rule, match):
    # get the value for the match's query_key (or none) to form the key used for the silence_cache.
    # Flatline ruletype sets "key" instead of the actual query_key
    # if isinstance(rule["type"], FlatlineRule) and "key" in match:
    #     return str(match["key"])
    return get_named_key_value(rule, match, "query_key")


def get_aggregation_key_value(rule, match):
    # get the value for the match's aggregation_key (or none) to form the key used for grouped aggregates.
    return get_named_key_value(rule, match, "aggregation_key")


def get_named_key_value(rule, match, key_name):
    # search the match for the key specified in the rule to get the value
    if key_name in rule:
        try:
            key_value = lookup_es_key(match, rule[key_name])
            if key_value is not None:
                # Only do the unicode conversion if we actually found something)
                # otherwise we might transform None --> 'None'
                key_value = str(key_value)
        except KeyError:
            # Some matches may not have the specified key
            # use a special token for these
            key_value = "_missing"
    else:
        key_value = None

    return key_value
