""" custom """
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.IndicatorProperties import IndicatorProperties


class HostProperties(IndicatorProperties):
    """
    URI:
    /<api version>/indicators/addresses/<INDICATOR VALUE>

    JSON DATA:
    {"id" : 1791117,
     "owner" : {
       "id" : 665,
       "name" : "Acme Corp",
       "type" : "Organization"
     },
     "dateAdded" : "2015-03-19T18:00:14Z",
     "lastModified" : "2015-03-19T18:00:14Z",
     "threatAssessRating" : 4.2,
     "threatAssessConfidence" : 91.75,
     "webLink" : "https://app.threatconnect.com/tc/auth/indicators/
         details/host.xhtml?host=web.agv-us.com&owner=Acme+Corp",
     "hostName" : "web.agv-us.com",
     "dnsActive" : "true",
     "whoisActive" : "true"}
    """

    def __init__(self):
        """ """
        super(HostProperties, self).__init__()

        # resource properties
        self._resource_key = 'host'
        self._resource_pagination = False
        self._resource_type = ResourceType.HOST
        self._resource_uri_attribute = 'hosts'

        # update data methods
        self._data_methods['dnsActive'] = {
            'get': 'get_dns_active',
            'set': 'set_dns_active',
            'var': '_dns_active'}
        self._data_methods['hostName'] = {
            'get': 'get_indicator',
            'set': 'set_hostname',
            'var': '_indicator'}
        self._data_methods['whoisActive'] = {
            'get': 'get_whois_active',
            'set': 'set_whois_active',
            'var': '_whois_active'}

    @property
    def indicator_owner_albellowed(self):
        """ """
        return False

    @property
    def indicator_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/%s/%s'
