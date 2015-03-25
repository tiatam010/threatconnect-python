""" custom """
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.IndicatorProperties import IndicatorProperties


class AddressProperties(IndicatorProperties):
    """
    URI:
    /<api version>/indicators/addresses/<INDICATOR VALUE>

    JSON Data:
    {"id" : 1792044,
     "owner" : {
       "id" : 665,
       "name" : "Acme Corp",
       "type" : "Organization"
     },
     "dateAdded" : "2015-03-20T05:34:26Z",
     "lastModified" : "2015-03-20T05:34:26Z",
     "webLink" : "https://app.threatconnect.com/tc/auth/indicators/
         details/address.xhtml?address=23.229.168.185&owner=Acme+Corp",
     "ip" : "23.229.168.185"
    }

    """

    def __init__(self):
        """ """
        super(AddressProperties, self).__init__()

        # resource properties
        self._resource_key = 'address'
        self._resource_pagination = False
        self._resource_type = ResourceType.ADDRESS
        self._resource_uri_attribute = 'addresses'

        # update data methods
        self._data_methods['ip'] = {
            'get': 'get_indicator',
            'set': 'set_ip',
            'var': '_indicator'}

    @property
    def indicator_owner_allowed(self):
        """ """
        return False

    @property
    def indicator_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/%s/%s'
