""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.GroupProperties import GroupProperties


class ThreatProperties(GroupProperties):
    """
    URI:
    /<api version>/groups/threats/<ID>

    JSON Data:
    {"id" : 728252,
     "name" : "Li Bermuda",
     "owner" : {
       "id" : 665,
       "name" : "Acme Corp",
       "type" : "Organization"
     },
     "dateAdded" : "2015-03-06T19:34:26Z",
     "webLink" : "https://app.threatconnect.com/tc/auth/threat/
         threat.xhtml?threat=728252"}
    """
    def __init__(self, action=PropertiesAction.READ):
        """ """
        super(ThreatProperties, self).__init__(action)

        # resource properties
        self._resource_key = 'threat'
        self._resource_pagination = False
        self._resource_type = ResourceType.THREAT
        self._resource_uri_attribute = 'threats'

        # update object attributes
        self._object_attributes.remove(ResourceMethods.type_attr)

    @property
    def id_owner_allowed(self):
        """ """
        return False

    @property
    def id_path(self):
        """ """
        return ResourceUri.THREATS.value + '/%s'
