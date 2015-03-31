""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.IndicatorProperties import IndicatorProperties


class EmailAddressProperties(IndicatorProperties):
    """
    URI:
    /<api version>/indicators/emailAddresses/<INDICATOR VALUE>

    JSON Data:
    {"id" : 1178651,
     "ownerName" : "Acme Corp",
     "dateAdded" : "2015-01-16T00:22:50Z",
     "lastModified" : "2015-01-16T00:22:50Z",
     "rating" : 5.0,
     "confidence" : 100,
     "webLink" : "https://app.threatconnect.com/tc/auth/indicators/
         details/emailaddress.xhtml?emailaddress=naseer%40digitallinx.com&owner=Acme+Corp",
     "description" : "Indicators from arachnophobia",
     "address" : "naseer@digitallinx.com"}
    """

    def __init__(self, action=PropertiesAction.READ):
        """ """
        super(EmailAddressProperties, self).__init__(action)

        # resource properties
        self._resource_key = 'emailAddress'
        self._resource_pagination = False
        self._resource_type = ResourceType.EMAIL_ADDRESS
        self._resource_uri_attribute = 'emailAddresses'

        # update object attributes
        self._object_attributes.append(ResourceMethods.summary_attr)
        self._object_attributes.append(ResourceMethods.address_attr)

    @property
    def indicator_owner_allowed(self):
        """ """
        return False

    @property
    def indicator_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/%s/%s'
