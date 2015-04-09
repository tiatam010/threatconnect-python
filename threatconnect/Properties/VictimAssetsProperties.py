""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.VictimsProperties import VictimsProperties


class VictimAssetsProperties(VictimsProperties):
    """
    URIs:
    /<api version>/victims/<ID>/victimAssets
    /<api version>/indicators/<INDICATOR TYPE>/<INDICATOR VALUE>/victimAssets
    /<api version>/groups/adversaries/<ID>/victimAssets
    /<api version>/groups/emails/<ID>/victimAssets
    /<api version>/groups/incidents/<ID>/victimAssets
    /<api version>/groups/signatures/<ID>/victimAssets
    /<api version>/groups/threats/<ID>/victimAssets

    JSON Data:
    {"id" : 695,
     "name" : "big_timmy@aol.com",
     "type" : "EmailAddress",
     "webLink" : "https://app.threatconnect.com/tc/auth/victim/victim.xhtml?victim=490"}
    """
    def __init__(self, http_method=PropertiesAction.GET):
        """ """
        super(VictimAssetsProperties, self).__init__(http_method)

        # resource properties
        self._resource_key = 'victimAsset'
        self._resource_pagination = False
        self._resource_type = ResourceType.VICTIM_ASSETS
        self._resource_uri_attribute = 'victimAssets'

        # update object attributes
        self._object_attributes.remove(ResourceMethods.nationality_attr)
        self._object_attributes.remove(ResourceMethods.org_attr)
        self._object_attributes.remove(ResourceMethods.suborg_attr)
        self._object_attributes.remove(ResourceMethods.work_location_attr)
        self._object_attributes.append(ResourceMethods.type_attr)

    @property
    def id_owner_allowed(self):
        """ """
        return False

    @property
    def id_path(self):
        """ """
        return ResourceUri.VICTIMS.value + '/%s/' + self._resource_uri_attribute

