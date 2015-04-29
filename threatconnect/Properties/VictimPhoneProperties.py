""" custom """
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Properties.VictimPhonesProperties import VictimPhonesProperties


class VictimPhoneProperties(VictimPhonesProperties):
    """
    URIs:
    /<api version>/victims/<ID>/victimAssets/phoneNumbers/<ID>
    /<api version>/indicators/<INDICATOR TYPE>/<INDICATOR VALUE>/victimAssets/phoneNumbers/<ID>
    /<api version>/groups/adversaries/<ID>/victimAssets/phoneNumbers/<ID>
    /<api version>/groups/emails/<ID>/victimAssets/phoneNumbers/<ID>
    /<api version>/groups/incidents/<ID>/victimAssets/phoneNumbers/<ID>
    /<api version>/groups/signatures/<ID>/victimAssets/phoneNumbers/<ID>
    /<api version>/groups/threats/<ID>/victimAssets/phoneNumbers/<ID>

    JSON Data:
    """

    def __init__(self, base_uri='v2', http_method=PropertiesAction.GET):
        """ """
        super(VictimPhoneProperties, self).__init__(base_uri, http_method)

        # resource properties
        self._resource_key = 'victimPhone'
        self._resource_pagination = False
        self._resource_type = ResourceType.VICTIM_PHONE
        self._resource_uri_attribute += '/{0}'
