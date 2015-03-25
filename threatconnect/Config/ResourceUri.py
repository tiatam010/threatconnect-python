""" third-party """
from enum import Enum

# api version
api_version = 'v2'


class ResourceUri(Enum):
    """ """
    ADVERSARIES = '/%s/groups/adversaries' % api_version
    ATTRIBUTES = '/%s/groups' % api_version
    DOCUMENTS = '/%s/groups/documents' % api_version
    EMAILS = '/%s/groups/emails' % api_version
    FILE_OCCURRENCES = '/%s/indicators/files' % api_version
    GROUPS = '/%s/groups' % api_version
    INCIDENTS = '/%s/groups/incidents' % api_version
    INDICATORS = '/%s/indicators' % api_version
    OWNERS = '/%s/owners' % api_version
    SECURITY_LABELS = '/%s/securityLabels' % api_version
    SIGNATURES = '/%s/groups/signatures' % api_version
    TAGS = '/%s/tags' % api_version
    THREATS = '/%s/groups/threats' % api_version
    VICTIMS = '/%s/victims' % api_version
