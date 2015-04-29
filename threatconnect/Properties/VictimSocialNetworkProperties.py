""" custom """
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Properties.VictimSocialNetworksProperties import VictimSocialNetworksProperties


class VictimSocialNetworkProperties(VictimSocialNetworksProperties):
    """
    URIs:
    /<api version>/victims/<ID>/victimAssets/socialNetworks/<ID>
    /<api version>/indicators/<INDICATOR TYPE>/<INDICATOR VALUE>/victimAssets/socialNetworks/<ID>
    /<api version>/groups/adversaries/<ID>/victimAssets/socialNetworks/<ID>
    /<api version>/groups/emails/<ID>/victimAssets/socialNetworks/<ID>
    /<api version>/groups/incidents/<ID>/victimAssets/socialNetworks/<ID>
    /<api version>/groups/signatures/<ID>/victimAssets/socialNetworks/<ID>
    /<api version>/groups/threats/<ID>/victimAssets/socialNetworks/<ID>

    JSON Data:
    """

    def __init__(self, base_uri='v2', http_method=PropertiesAction.GET):
        """ """
        super(VictimSocialNetworkProperties, self).__init__(base_uri, http_method)

        # resource properties
        self._resource_key = 'victimSocialNetwork'
        self._resource_pagination = False
        self._resource_type = ResourceType.VICTIM_SOCIAL_NETWORK
        self._resource_uri_attribute += '/{0}'
