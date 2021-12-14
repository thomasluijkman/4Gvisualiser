def safe_dict_get(dictionary, key, default=None):
    try:
        retval = dictionary[key]
    except KeyError:
        retval = default
    return retval