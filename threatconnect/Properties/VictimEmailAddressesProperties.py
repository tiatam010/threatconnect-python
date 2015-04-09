""" custom """
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Properties.VictimAssetsProperties import VictimAssetsProperties


class VictimEmailAddressesProperties(VictimAssetsProperties):
    """
    URIs:
    /<api version>/victims/<ID>/victimAssets/emailAddresses
    /<api version>/indicators/<INDICATOR TYPE>/<INDICATOR VALUE>/victimAssets/emailAddresses
    /<api version>/groups/adversaries/<ID>/victimAssets/emailAddresses
    /<api version>/groups/emails/<ID>/victimAssets/emailAddresses
    /<api version>/groups/incidents/<ID>/victimAssets/emailAddresses
    /<api version>/groups/signatures/<ID>/victimAssets/emailAddresses
    /<api version>/groups/threats/<ID>/victimAssets/emailAddresses

    JSON Data:
    """

    def __init__(self):
        """ """
        super(VictimEmailAddressesProperties, self).__init__()

        # resource properties
        self._resource_key = 'victimEmailAddress'
        self._resource_pagination = False
        self._resource_type = ResourceType.VICTIM_EMAIL_ADDRESSES
        self._resource_uri_attribute += '/emailAddresses'
