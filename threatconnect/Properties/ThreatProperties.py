""" custom """
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

    def __init__(self):
        """ """
        super(ThreatProperties, self).__init__()

        # resource properties
        self._resource_key = 'threat'
        self._resource_pagination = False
        self._resource_type = ResourceType.THREAT
        self._resource_uri_attribute = 'threats'

        # update data methods
        self._data_methods.pop('ownerName')
        self._data_methods.pop('type')
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
        return ResourceUri.THREATS.value + '/%s'
