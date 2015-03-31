""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.GroupProperties import GroupProperties


class IncidentProperties(GroupProperties):
    """
    URIs:
    /<api version>/groups/incident/<ID>

    JSON Data:
    {"id" : 126938,
     "name" : "[AA] Brand Abuse",
     "owner" : {
       "id" : 665,
       "name" : "Acme Corp",
       "type" : "Organization"
     },
     "dateAdded" : "2014-09-10T19:11:15Z",
     "webLink" : "https://app.threatconnect.com/tc/auth/incident/
         incident.xhtml?incident=126938",
     "eventDate" : "2014-09-10T00:00:00Z"}

    """

    def __init__(self, action=PropertiesAction.READ):
        """ """
        super(IncidentProperties, self).__init__(action)

        # resource properties
        self._resource_key = 'incident'
        self._resource_pagination = False
        self._resource_type = ResourceType.INCIDENT
        self._resource_uri_attribute = 'incidents'

        # update object attributes
        self._object_attributes.remove(ResourceMethods.type_attr)
        self._object_attributes.append(ResourceMethods.event_data_attr)

    @property
    def id_owner_allowed(self):
        """ """
        return False

    @property
    def id_path(self):
        """ """
        return ResourceUri.INCIDENTS.value + '/%s'
