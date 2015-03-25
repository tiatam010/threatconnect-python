""" custom """
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

    def __init__(self):
        """ """
        super(IncidentProperties, self).__init__()

        # resource properties
        self._resource_key = 'incident'
        self._resource_pagination = False
        self._resource_type = ResourceType.INCIDENT
        self._resource_uri_attribute = 'incidents'

        # data methods
        self._data_methods.pop('ownerName')
        self._data_methods.pop('type')
        self._data_methods['eventDate'] = {
            'get': 'get_event_date',
            'set': 'set_event_date',
            'var': '_event_date'}
        self._data_methods['owner'] = {
            'get': 'get_owner_name',
            'set': 'set_owner',
            'var': '_owner_name'}

    @property
    def id_owner_allowed(self):
        """ """
        return False

    @property
    def id_path(self):
        """ """
        return ResourceUri.INCIDENTS.value + '/%s'
