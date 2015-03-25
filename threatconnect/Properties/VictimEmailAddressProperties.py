""" custom """
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Properties.VictimEmailAddressesProperties import VictimEmailAddressesProperties


class VictimEmailAddressProperties(VictimEmailAddressesProperties):
    """
    URIs:
    /<api version>/victims/<ID>/victimAssets/emailAddresses/<ID>
    /<api version>/indicators/<INDICATOR TYPE>/<INDICATOR VALUE>/victimAssets/emailAddresses/<ID>
    /<api version>/groups/adversaries/<ID>/victimAssets/emailAddresses/<ID>
    /<api version>/groups/emails/<ID>/victimAssets/emailAddresses/<ID>
    /<api version>/groups/incidents/<ID>/victimAssets/emailAddresses/<ID>
    /<api version>/groups/signatures/<ID>/victimAssets/emailAddresses/<ID>
    /<api version>/groups/threats/<ID>/victimAssets/emailAddresses/<ID>

    JSON Data:
    """

    def __init__(self):
        """ """
        super(VictimEmailAddressProperties, self).__init__()

        # resource properties
        self._resource_key = 'victimEmailAddress'
        self._resource_pagination = False
        self._resource_type = ResourceType.VICTIM_EMAIL_ADDRESS
        self._resource_uri_attribute += '/%s'
