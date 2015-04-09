""" custom """
from threatconnect.Config.ResourceRegexes import indicators_regex
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


def get_resource_type(indicator):
    """Get resource type enum from an indicator."""
    for indicator_type, regex in indicators_regex.items():
        for rex in regex:
            if rex.match(indicator):
                return ResourceType[indicator_type]
    return None


def get_resource_group_type(group_type):
    """Get resource type enum from a group type."""
    return g_type_to_r_type[group_type]


def validate_indicator(indicator):
    """ """
    for indicator_type, regex in indicators_regex.items():
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
