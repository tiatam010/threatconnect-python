""" custom """
from threatconnect.Config.ResourceRegexes import indicators_regex, md5_re, sha1_re, sha256_re
from threatconnect.Config.ResourceType import ResourceType

# group type to resource type mapping
g_type_to_r_type = {
    'Address': ResourceType.EMAILS,
    'Adversary': ResourceType.ADVERSARIES,
    'Document': ResourceType.DOCUMENTS,
    'Email': ResourceType.EMAILS,
    'Incident': ResourceType.INCIDENTS,
    'Signature': ResourceType.SIGNATURES,
    'Threat': ResourceType.THREATS}

# indicator type to resource type mapping
i_type_to_r_type = {
    'Address': ResourceType.ADDRESSES,
    'EmailAddress': ResourceType.EMAIL_ADDRESSES,
    'File': ResourceType.FILES,
    'Host': ResourceType.HOSTS,
    'URL': ResourceType.URLS}


def get_hash_type(indicator):
    """Get hash type from an indicator."""
    if md5_re.match(indicator):
        return 'MD5'
    elif sha1_re.match(indicator):
        return 'SHA1'
    elif sha256_re.match(indicator):
        return 'SHA256'


def get_resource_type(indicator):
    """Get resource type enum from an indicator."""
    for indicator_type, regex in indicators_regex.viewitems():
        for rex in regex:
            if rex.match(indicator):
                return ResourceType[indicator_type]
    return None


def get_resource_group_type(group_type):
    """Get resource type enum from a group type."""
    return g_type_to_r_type[group_type]


def get_resource_indicator_type(indicator_type):
    """Get resource type enum from a indicator type."""
    return i_type_to_r_type[indicator_type]


def validate_indicator(indicator):
    """ """
    for indicator_type, regex in indicators_regex.viewitems():
        for rex in regex:
            if rex.match(str(indicator)):
                return True
    return False


def validate_rating(rating):
    """ """
    if rating in ["1.0", "2.0", "3.0", "4.0", "5.0", 0, 1, 2, 3, 4, 5]:
        return True

    # todo - make this a bit more robust, 0?
    return False
