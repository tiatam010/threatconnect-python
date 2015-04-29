""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
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

    def __init__(self, base_uri='v2', http_method=PropertiesAction.GET):
        """ """
        super(VictimEmailAddressProperties, self).__init__(base_uri, http_method)

        # resource properties
        self._resource_key = 'victimEmailAddress'
        self._resource_pagination = False
        self._resource_type = ResourceType.VICTIM_EMAIL_ADDRESS
        self._resource_uri_attribute += '/{0}'

        # update object attributes
        self._object_attributes.remove(ResourceMethods.name_attr)
