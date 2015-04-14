""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
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
    def __init__(self, base_uri='v2', http_method=PropertiesAction.GET):
        """ """
        super(SignatureProperties, self).__init__(base_uri, http_method)

        # resource properties
        self._resource_key = 'signature'
        self._resource_pagination = False
        self._resource_type = ResourceType.SIGNATURE
        self._resource_uri_attribute = 'signatures'

        # update object attributes
        self._object_attributes.remove(ResourceMethods.type_attr)
        self._object_attributes.append(ResourceMethods.download_attr)
        self._object_attributes.append(ResourceMethods.file_name_attr)
        self._object_attributes.append(ResourceMethods.file_text_attr)
        self._object_attributes.append(ResourceMethods.file_type_attr)

    @property
    def id_owner_allowed(self):
        """ """
        return False

    @property
    def id_path(self):
        """ """
        return ResourceUri.SIGNATURES.value + '/%s'
