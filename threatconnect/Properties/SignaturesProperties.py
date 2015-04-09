""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Properties.GroupsProperties import GroupsProperties


class SignaturesProperties(GroupsProperties):
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
    def __init__(self, http_method=PropertiesAction.GET):
        """ """
        super(SignaturesProperties, self).__init__(http_method)

        # resource properties
        self._resource_key = 'signature'
        self._resource_pagination = True
        self._resource_type = ResourceType.SIGNATURES
        self._resource_uri_attribute += '/signatures'

        # update object attributes
        self._object_attributes.remove(ResourceMethods.type_attr)
        self._object_attributes.append(ResourceMethods.file_type_attr)

        # update filter methods
        self._filter_methods.remove('add_signature_id')
        self._filter_methods.append('add_id')
        self._filter_methods.append('add_file_type')

