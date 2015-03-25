""" standard """
import operator

""" third-party """
from enum import Enum


class ApiStatus(Enum):
    """ """
    FAILURE = 1
    SUCCESS = 0


class FilterOperator(Enum):
    """ """
    # Query Operator
    EQ = operator.eq
    NE = operator.ne
    GT = operator.gt
    GE = operator.ge
    LT = operator.lt
    LE = operator.le


class FilterSetOperator(Enum):
    """ """
    # Query Set Operator
    AND = 'and'
    OR = 'or'


class ResourceKey(Enum):
    """ """
    # Group Resources
    ADVERSARY = 'adversary'
    ADVERSARIES = 'adversary'
    ATTRIBUTES = 'attribute'
    DNS_RESOLUTIONS = 'dnsResolution'
    DOCUMENT = 'document'
    DOCUMENTS = 'document'
    EMAIL = 'email'
    EMAILS = 'email'
    FILE_OCCURRENCE = 'fileOccurrence'
    FILE_OCCURRENCES = 'fileOccurrence'
    INCIDENT = 'incident'
    INCIDENTS = 'incident'
    INDICATORS = 'indicator'
    GROUPS = 'group'
    OWNERS = 'owner'
    SECURITY_LABEL = 'securityLabel'
    SECURITY_LABELS = 'securityLabel'
    SIGNATURE = 'signature'
    SIGNATURES = 'signature'
    TAG = 'tag'
    TAGS = 'tag'
    THREAT = 'threat'
    THREATS = 'threat'
    VICTIM = 'victim'
    VICTIMS = 'victim'
    VICTIM_ASSETS = 'victimAsset'
    VICTIM_EMAIL_ADDRESS = 'victimEmailAddress'
    VICTIM_EMAIL_ADDRESSES = 'victimEmailAddress'
    VICTIM_NETWORK_ACCOUNT = 'victimNetworkAccount'
    VICTIM_NETWORK_ACCOUNTS = 'victimNetworkAccount'
    VICTIM_PHONE = 'victimPhone'
    VICTIM_PHONES = 'victimPhone'
    VICTIM_SOCIAL_NETWORK = 'victimSocialNetwork'
    VICTIM_SOCIAL_NETWORKS = 'victimSocialNetwork'
    VICTIM_WEBSITE = 'victimWebSite'
    VICTIM_WEBSITES = 'victimWebSite'

    # Indicator Resources
    ADDRESS = 'address'
    ADDRESSES = 'address'
    EMAIL_ADDRESS = 'emailAddress'
    EMAIL_ADDRESSES = 'emailAddress'
    FILE = 'file'
    FILES = 'file'
    HOST = 'host'
    HOSTS = 'host'
    URL = 'url'
    URLS = 'url'
