""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Properties.VictimAssetsProperties import VictimAssetsProperties


class VictimPhonesProperties(VictimAssetsProperties):
    """
    URIs:
    /<api version>/victims/<ID>/victimAssets/phoneNumbers
    /<api version>/indicators/<INDICATOR TYPE>/<INDICATOR VALUE>/victimAssets/phoneNumbers
    /<api version>/groups/adversaries/<ID>/victimAssets/phoneNumbers
    /<api version>/groups/emails/<ID>/victimAssets/phoneNumbers
    /<api version>/groups/incidents/<ID>/victimAssets/phoneNumbers
    /<api version>/groups/signatures/<ID>/victimAssets/phoneNumbers
    /<api version>/groups/threats/<ID>/victimAssets/phoneNumbers

    JSON Data:
    """

    def __init__(self, base_uri='v2', http_method=PropertiesAction.GET):
        """ """
        super(VictimPhonesProperties, self).__init__(base_uri, http_method)

        # resource properties
        self._resource_key = 'victimPhone'
        self._resource_pagination = False
        self._resource_type = ResourceType.VICTIM_PHONES
        self._resource_uri_attribute += '/phoneNumbers'

        # update object attributes
        self._object_attributes.remove(ResourceMethods.name_attr)
