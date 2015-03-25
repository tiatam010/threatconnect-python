""" custom """
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.GroupProperties import GroupProperties


class DocumentProperties(GroupProperties):
    """
    URI:
    /<api version>/groups/adversaries/<ID>

    JSON Data
    {"document" : {
     "id" : 734899,
     "name" : "20030626 IIS Log",
     "owner" : {
       "id" : 665,
       "name" : "Acme Corp",
       "type" : "Organization"
     },
     "dateAdded" : "2015-03-13T18:10:57Z",
     "webLink" : "https://app.threatconnect.com/tc/auth/document/document.xhtml?document=734899",
     "fileName" : "20030626 IIS Logs.txt",
     "fileSize" : 5979,
     "status" : "Success"}
    """

    def __init__(self):
        """ """
        super(DocumentProperties, self).__init__()

        # resource properties
        self._resource_key = 'document'
        self._resource_pagination = False
        self._resource_type = ResourceType.DOCUMENT
        self._resource_uri_attribute = 'documents'

        # update data methods
        self._data_methods.pop('ownerName')
        self._data_methods.pop('type')
        self._data_methods['fileName'] = {
            'get': 'get_file_name',
            'set': 'set_file_name',
            'var': '_file_name'}
        self._data_methods['fileSize'] = {
            'get': 'get_file_size',
            'set': 'set_file_size',
            'var': '_file_size'}
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
        return ResourceUri.DOCUMENTS.value + '/%s'
