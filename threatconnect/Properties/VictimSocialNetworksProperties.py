""" custom """
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

    def __init__(self):
        """ """
        super(VictimSocialNetworksProperties, self).__init__()

        # resource properties
        self._resource_key = 'victimSocialNetwork'
        self._resource_pagination = False
        self._resource_type = ResourceType.VICTIM_SOCIAL_NETWORKS
        self._resource_uri_attribute += '/socialNetworks'

        # data methods
        self._data_methods.pop('name')

