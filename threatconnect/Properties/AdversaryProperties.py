""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.GroupProperties import GroupProperties


class AdversaryProperties(GroupProperties):
    """
    URI:
    /<api version>/groups/adversaries/<ID>

    JSON Data:
    {"id" : 734631,
     "name" : "Cyber Thief X",
     "owner" : {
       "id" : 665,
       "name" : "Acme Corp",
       "type" : "Organization"
     },
     "dateAdded" : "2015-03-12T15:46:08Z",
     "webLink" : "https://app.threatconnect.com/tc/auth/adversary/
         adversary.xhtml?adversary=734631"}
    """
    def __init__(self, http_method=PropertiesAction.GET):
        """ """
        super(AdversaryProperties, self).__init__(http_method)

        # resource properties
        self._resource_key = 'adversary'
        self._resource_pagination = False
        self._resource_type = ResourceType.ADVERSARY
        self._resource_uri_attribute = 'adversaries'

        # update object attributes
        self._object_attributes.remove(ResourceMethods.type_attr)

    @property
    def id_owner_allowed(self):
        """ """
        return False

    @property
    def id_path(self):
        """ """
        return ResourceUri.ADVERSARIES.value + '/%s'
