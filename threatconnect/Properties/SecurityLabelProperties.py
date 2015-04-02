""" custom """
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.SecurityLabelsProperties import SecurityLabelsProperties


class SecurityLabelProperties(SecurityLabelsProperties):
    """
    URIs:
    /<api version>/securityLabels/<LABEL NAME>
    /<api version>/indicators/<INDICATOR TYPE>/<INDICATOR VALUE>/securityLabels/<LABEL NAME>
    /<api version>/groups/adversaries/<ID>/securityLabels/<LABEL NAME>
    /<api version>/groups/emails/<ID>/securityLabels/<LABEL NAME>
    /<api version>/groups/incidents/<ID>/securityLabels/<LABEL NAME>
    /<api version>/groups/signatures/<ID>/securityLabels/<LABEL NAME>
    /<api version>/groups/threats/<ID>/securityLabels/<LABEL NAME>

    JSON Data:
    {"name" : "DO NOT SHARE",
     "description" : "This data is ACME CONFIDENTIAL and is not approved for external release.",
     "dateAdded" : "2014-03-17T15:29:53Z"}
    """
    def __init__(self, http_method=PropertiesAction.GET):
        """ """
        super(SecurityLabelProperties, self).__init__(http_method)

        # resource properties
        self._resource_key = 'securityLabel'
        self._resource_pagination = False
        self._resource_type = ResourceType.SECURITY_LABEL
        self._resource_uri_attribute += '/%s'

    @property
    def name_owner_allowed(self):
        return True

    @property
    def name_path(self):
        return ResourceUri.VICTIMS.value + '/%s'
