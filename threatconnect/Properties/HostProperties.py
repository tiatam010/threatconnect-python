""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
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
    def __init__(self, http_method=PropertiesAction.GET):
        """ """
        super(HostProperties, self).__init__(http_method)

        # resource properties
        self._resource_key = 'host'
        self._resource_pagination = False
        self._resource_type = ResourceType.HOST
        self._resource_uri_attribute = 'hosts'

        # update object attributes
        self._object_attributes.remove(ResourceMethods.summary_attr)
        self._object_attributes.append(ResourceMethods.hostname_attr)

    @property
    def indicator_owner_allowed(self):
        """ """
        return False

    @property
    def indicator_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/%s/%s'
