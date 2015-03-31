""" custom """
import types
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Properties.IndicatorsProperties import IndicatorsProperties


class AddressesProperties(IndicatorsProperties):
    """
    URIs:
    /<api version>/indicators/addresses
    /<api version>/groups/adversaries/<ID>/indicators/addresses
    /<api version>/groups/emails/<ID>/indicators/addresses
    /<api version>/groups/incidents/<ID>/indicators/addresses
    /<api version>/groups/signatures/<ID>/indicators/addresses
    /<api version>/groups/threats/<ID>/indicators/addresses
    /<api version>/securityLabels/<security label>/indicators/addresses
    /<api version>/tags/<tag name>/indicators/addresses
    /<api version>/victims/<ID>/indicators/addresses

    JSON Data:
    {"id" : 1808273,
     "ownerName" : "Acme Corp",
     "dateAdded" : "2015-03-21T22:03:34Z",
     "lastModified" : "2015-03-21T22:03:34Z",
     "rating" : 4.0,
     "confidence" : 72,
     "webLink" : "https://app.threatconnect.com/tc/auth/indicators/
         details/address.xhtml?address=52.64.21.202&owner=Acme+Corp",
     "description" : "test",
     "ip" : "52.64.21.202"}
    """

    def __init__(self, action=PropertiesAction.READ):
        """ """
        super(AddressesProperties, self).__init__(action)

        # resource properties
        self._resource_key = 'address'
        self._resource_pagination = True
        self._resource_type = ResourceType.ADDRESSES
        self._resource_uri_attribute += '/addresses'

        self._object_attributes.remove(ResourceMethods.summary_attr)
        self._object_attributes.append(ResourceMethods.ip_attr)
