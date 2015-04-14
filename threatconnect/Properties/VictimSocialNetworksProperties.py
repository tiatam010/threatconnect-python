""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Properties.VictimAssetsProperties import VictimAssetsProperties


class VictimSocialNetworksProperties(VictimAssetsProperties):
    """
    URIs:
    /<api version>/victims/<ID>/victimAssets/socialNetworks
    /<api version>/indicators/<INDICATOR TYPE>/<INDICATOR VALUE>/victimAssets/socialNetworks
    /<api version>/groups/adversaries/<ID>/victimAssets/socialNetworks
    /<api version>/groups/emails/<ID>/victimAssets/socialNetworks
    /<api version>/groups/incidents/<ID>/victimAssets/socialNetworks
    /<api version>/groups/signatures/<ID>/victimAssets/socialNetworks
    /<api version>/groups/threats/<ID>/victimAssets/socialNetworks

    JSON Data:
    """

    def __init__(self, base_uri='v2', http_method=PropertiesAction.GET):
        """ """
        super(VictimSocialNetworksProperties, self).__init__(base_uri, http_method)

        # resource properties
        self._resource_key = 'victimSocialNetwork'
        self._resource_pagination = False
        self._resource_type = ResourceType.VICTIM_SOCIAL_NETWORKS
        self._resource_uri_attribute += '/socialNetworks'

        # update object attributes
        self._object_attributes.remove(ResourceMethods.name_attr)

