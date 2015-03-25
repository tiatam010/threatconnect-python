""" custom """
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Properties.GroupsProperties import GroupsProperties


class SignaturesProperties(GroupsProperties):
    """ """
    def __init__(self):
        """
        URIs:
        /<api version>/groups/signatures
        /<api version>/indicators/<indicator type>/<value>/groups/signatures
        /<api version>/groups/adversaries/<ID>/groups/signatures
        /<api version>/groups/emails/<ID>/groups/signatures
        /<api version>/groups/incidents/<ID>/groups/signatures
        /<api version>/groups/threats/<ID>/groups/signatures
        /<api version>/securityLabels/<security label>/groups/signatures
        /<api version>/tags/<tag name>/groups/signatures
        /<api version>/victims/<ID>/groups/signatures

        JSON Data:
        {"id" : 132117,
         "name" : "20140220B.rules",
         "ownerName" : "Acme Corp",
         "dateAdded" : "2014-10-15T18:49:33Z",
         "webLink" : "https://app.threatconnect.com/tc/auth/signature/signature.xhtml?signature=132117",
         "fileType" : "Snort"}
        """
        super(SignaturesProperties, self).__init__()

        # resource properties
        self._resource_key = 'signature'
        self._resource_pagination = True
        self._resource_type = ResourceType.SIGNATURES
        self._resource_uri_attribute += '/signatures'

        # update data methods
        self._data_methods.pop('type')
        self._data_methods['fileType'] = {
            'get': 'get_file_type',
            'set': 'set_file_type',
            'var': '_file_type'}

        # update filter methods
        self._filter_methods.remove('add_signature_id')
        self._filter_methods.append('add_id')

