""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
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

    def __init__(self, action=PropertiesAction.READ):
        """ """
        super(DocumentProperties, self).__init__(action)

        # resource properties
        self._resource_key = 'document'
        self._resource_pagination = False
        self._resource_type = ResourceType.DOCUMENT
        self._resource_uri_attribute = 'documents'

        # update object attributes
        self._object_attributes.remove(ResourceMethods.type_attr)
        self._object_attributes.append(ResourceMethods.file_name_attr)
        self._object_attributes.append(ResourceMethods.file_size_attr)

    @property
    def id_owner_allowed(self):
        """ """
        return False

    @property
    def id_path(self):
        """ """
        return ResourceUri.DOCUMENTS.value + '/%s'
