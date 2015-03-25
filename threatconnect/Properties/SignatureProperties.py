""" custom """
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.GroupProperties import GroupProperties


class SignatureProperties(GroupProperties):
    """
    URI:
    /<api version>/groups/signatures/<ID>

    JSON Data:
    {"id" : 675649,
     "name" : "APT_EPO_HBS.yara",
     "owner" : {
       "id" : 665,
       "name" : "Acme Corp",
       "type" : "Organization"
     },
     "dateAdded" : "2015-01-28T03:27:54Z",
     "webLink" : "https://app.threatconnect.com/tc/auth/signature/signature.xhtml?signature=675649",
     "fileType" : "YARA",
     "fileName" : "APT_EPO_HBS.yara"}

    """

    def __init__(self):
        """ """
        super(SignatureProperties, self).__init__()

        # resource properties
        self._resource_key = 'signature'
        self._resource_pagination = False
        self._resource_type = ResourceType.SIGNATURE
        self._resource_uri_attribute = 'signatures'

        # update data methods
        self._data_methods.pop('ownerName')
        self._data_methods.pop('type')
        self._data_methods['download'] = {
            'get': 'get_download',
            'set': 'set_download',
            'var': '_download'}
        self._data_methods['fileName'] = {
            'get': 'get_file_name',
            'set': 'set_file_name',
            'var': '_file_name'}
        self._data_methods['fileType'] = {
            'get': 'get_file_type',
            'set': 'set_file_type',
            'var': '_file_name'}
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
        return ResourceUri.SIGNATURES.value + '/%s'
