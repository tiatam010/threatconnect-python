""" custom """
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Properties.VictimWebSitesProperties import VictimWebSitesProperties


class VictimWebSiteProperties(VictimWebSitesProperties):
    """
    URIs:
    /<api version>/victims/<ID>/victimAssets/webSites/<ID>
    /<api version>/indicators/<INDICATOR TYPE>/<INDICATOR VALUE>/victimAssets/webSites/<ID>
    /<api version>/groups/adversaries/<ID>/victimAssets/webSites/<ID>
    /<api version>/groups/emails/<ID>/victimAssets/webSites/<ID>
    /<api version>/groups/incidents/<ID>/victimAssets/webSites/<ID>
    /<api version>/groups/signatures/<ID>/victimAssets/webSites/<ID>
    /<api version>/groups/threats/<ID>/victimAssets/webSites/<ID>

    JSON Data:
    """

    def __init__(self):
        """ """
        super(VictimWebSiteProperties, self).__init__()

        # resource properties
        self._resource_key = 'victimWebSite'
        self._resource_pagination = False
        self._resource_type = ResourceType.VICTIM_WEBSITE
        self._resource_uri_attribute += '/%s'
