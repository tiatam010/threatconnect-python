""" custom """
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Properties.GroupsProperties import GroupsProperties


class DocumentsProperties(GroupsProperties):
    """ """
    def __init__(self):
        """
        URIs:
        /<api version>/groups/documents
        /<api version>/indicators/<indicator type>/<value>/groups/documents
        /<api version>/groups/emails/<ID>/groups/documents
        /<api version>/groups/incidents/<ID>/groups/documents
        /<api version>/groups/signatures/<ID>/groups/signatures
        /<api version>/groups/threats/<ID>/groups/documents
        /<api version>/securityLabels/<security label>/groups/documents
        /<api version>/tags/<tag name>/groups/documents
        /<api version>/victims/<ID>/groups/documents

        JSON Data:
        {"id" : 675385,
         "name" : "Test4",
         "ownerName" : "Acme Corp",
         "dateAdded" : "2015-01-26T14:14:37Z",
         "webLink" : "https://app.threatconnect.com/tc/auth/document/document.xhtml?document=675385"}
        """
        super(DocumentsProperties, self).__init__()

        # resource properties
        self._resource_key = 'document'
        self._resource_pagination = True
        self._resource_type = ResourceType.DOCUMENTS
        self._resource_uri_attribute += '/' + 'documents'

        # update data methods
        self._data_methods.pop('type')

        # update filter methods
        self._filter_methods.remove('add_adversary_id')
        self._filter_methods.append('add_id')
