""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Properties.VictimAssetsProperties import VictimAssetsProperties


class VictimWebSitesProperties(VictimAssetsProperties):
    """
    URIs:
    /<api version>/victims/<ID>/victimAssets/webSites
    /<api version>/indicators/<INDICATOR TYPE>/<INDICATOR VALUE>/victimAssets/webSites
    /<api version>/groups/adversaries/<ID>/victimAssets/webSites
    /<api version>/groups/emails/<ID>/victimAssets/webSites
    /<api version>/groups/incidents/<ID>/victimAssets/webSites
    /<api version>/groups/signatures/<ID>/victimAssets/webSites
    /<api version>/groups/threats/<ID>/victimAssets/webSites

    JSON Data:
    """

    def __init__(self, base_uri='v2', http_method=PropertiesAction.GET):
        """ """
        super(VictimWebSitesProperties, self).__init__(base_uri, http_method)

        # resource properties
        self._resource_key = 'victimWebSite'
        self._resource_pagination = False
        self._resource_type = ResourceType.VICTIM_WEBSITES
        self._resource_uri_attribute += '/webSites'

        # update object attributes
        self._object_attributes.remove(ResourceMethods.name_attr)

