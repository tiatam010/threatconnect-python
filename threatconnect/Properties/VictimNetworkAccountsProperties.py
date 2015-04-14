""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Properties.VictimAssetsProperties import VictimAssetsProperties


class VictimNetworkAccountsProperties(VictimAssetsProperties):
    """
    URIs:
    /<api version>/victims/<ID>/victimAssets/networkAccounts
    /<api version>/indicators/<INDICATOR TYPE>/<INDICATOR VALUE>/victimAssets/networkAccounts
    /<api version>/groups/adversaries/<ID>/victimAssets/networkAccounts
    /<api version>/groups/emails/<ID>/victimAssets/networkAccounts
    /<api version>/groups/incidents/<ID>/victimAssets/networkAccounts
    /<api version>/groups/signatures/<ID>/victimAssets/networkAccounts
    /<api version>/groups/threats/<ID>/victimAssets/networkAccounts

    JSON Data:
    """

    def __init__(self, base_uri='v2', http_method=PropertiesAction.GET):
        """ """
        super(VictimNetworkAccountsProperties, self).__init__(base_uri, http_method)

        # resource properties
        self._resource_key = 'victimNetworkAccount'
        self._resource_pagination = False
        self._resource_type = ResourceType.VICTIM_NETWORK_ACCOUNTS
        self._resource_uri_attribute += '/networkAccounts'

        # update object attributes
        self._object_attributes.remove(ResourceMethods.name_attr)

