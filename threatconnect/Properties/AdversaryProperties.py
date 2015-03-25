""" custom """
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

    def __init__(self):
        """ """
        super(AdversaryProperties, self).__init__()

        # resource properties
        self._resource_key = 'adversary'
        self._resource_pagination = False
        self._resource_type = ResourceType.ADVERSARY
        self._resource_uri_attribute = 'adversaries'

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
        return ResourceUri.ADVERSARIES.value + '/%s'
