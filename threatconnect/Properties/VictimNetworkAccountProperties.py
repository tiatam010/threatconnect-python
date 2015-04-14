""" custom """
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Properties.VictimNetworkAccountsProperties import VictimNetworkAccountsProperties


class VictimNetworkAccountProperties(VictimNetworkAccountsProperties):
    """
    URIs:
    /<api version>/victims/<ID>/victimAssets/networkAccounts/<ID>
    /<api version>/indicators/<INDICATOR TYPE>/<INDICATOR VALUE>/victimAssets/networkAccounts/<ID>
    /<api version>/groups/adversaries/<ID>/victimAssets/networkAccounts/<ID>
    /<api version>/groups/emails/<ID>/victimAssets/networkAccounts/<ID>
    /<api version>/groups/incidents/<ID>/victimAssets/networkAccounts/<ID>
    /<api version>/groups/signatures/<ID>/victimAssets/networkAccounts/<ID>
    /<api version>/groups/threats/<ID>/victimAssets/networkAccounts/<ID>

    JSON Data:
    """

    def __init__(self, base_uri='v2', http_method=PropertiesAction.GET):
        """ """
        super(VictimNetworkAccountProperties, self).__init__(base_uri, http_method)

        # resource properties
        self._resource_key = 'victimNetworkAccount'
        self._resource_pagination = False
        self._resource_type = ResourceType.VICTIM_NETWORK_ACCOUNT
        self._resource_uri_attribute += '/%s'
