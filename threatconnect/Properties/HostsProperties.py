""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Properties.IndicatorsProperties import IndicatorsProperties


class HostsProperties(IndicatorsProperties):
    """
    URIs:
    /<api version>/indicators/hosts
    /<api version>/groups/adversaries/<ID>/indicators/hosts
    /<api version>/groups/emails/<ID>/indicators/hosts
    /<api version>/groups/incidents/<ID>/indicators/hosts
    /<api version>/groups/signatures/<ID>/indicators/hosts
    /<api version>/groups/threats/<ID>/indicators/hosts
    /<api version>/securityLabels/<security label>/indicators/hosts
    /<api version>/tags/<tag name>/indicators/hosts
    /<api version>/victims/<ID>/indicators/addresses

    JSON Data:
    {"id" : 1683035,
     "ownerName" : "Acme Corp",
     "dateAdded" : "2015-03-10T14:00:59Z",
     "lastModified" : "2015-03-10T14:00:59Z",
     "rating" : 4.0,
     "confidence" : 72,
     "webLink" : "https://app.threatconnect.com/tc/auth/indicators/
         details/host.xhtml?host=rss.openpicz.net&owner=Acme+Corp",
     "description" : "Steal Rat Indicators",
     "hostName" : "rss.openpicz.net"}
    """
    def __init__(self, http_method=PropertiesAction.GET):
        """ """
        super(HostsProperties, self).__init__(http_method)

        # resource properties
        self._resource_key = 'host'
        self._resource_pagination = True
        self._resource_type = ResourceType.HOSTS
        self._resource_uri_attribute += '/hosts'

        # update object attributes
        self._object_attributes.remove(ResourceMethods.summary_attr)
        self._object_attributes.append(ResourceMethods.hostname_attr)
