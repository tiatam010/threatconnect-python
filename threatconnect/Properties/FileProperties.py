""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.IndicatorProperties import IndicatorProperties


class FileProperties(IndicatorProperties):
    """
    URI:
    /<api version>/indicators/files/<INDICATOR VALUE>

    JSON Data:
    {"id": 199,
     "owner":       {
        "id": 1,
        "name": "Organization Name",
        "type": "Organization"
     },
     "dateAdded": "2013-08-21T14:14:42Z",
     "lastModified": "2013-08-21T14:14:42Z",
     "webLink":  "https://app.threatconnect.com/tc/auth/indicators/
         details/file.xhtml?file=A35A766A9F881A8E6B01BBBC0D6BE829&owner=Organization Name",
     "md5": "A35A766A9F881A8E6B01BBBC0D6BE829",
     "sha1": "9F8CC0A150D272D9393F86B5F5F2D1265E8917D1",
     "sha256": "B4C1E9C99F861A4DD7654DCC3548AB5DDC15EE5FEB9690B9F716C4849714B20D"}
    """
    def __init__(self, http_method=PropertiesAction.GET):
        """ """
        super(FileProperties, self).__init__(http_method)

        # resource properties
        self._resource_key = 'file'
        self._resource_pagination = False
        self._resource_type = ResourceType.FILE
        self._resource_uri_attribute = 'files'

        # update object attributes
        self._object_attributes.remove(ResourceMethods.summary_attr)
        self._object_attributes.append(ResourceMethods.hash_attr)

    @property
    def indicator_owner_allowed(self):
        """ """
        return False

    @property
    def indicator_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/%s/%s'
