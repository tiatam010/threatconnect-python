""" custom """
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.VictimsProperties import VictimsProperties


class VictimProperties(VictimsProperties):
    """
    URIs:
    /<api version>/victims/<ID>
    /<api version>/indicators/<INDICATOR TYPE>/<INDICATOR VALUE>/victims/<ID>
    /<api version>/groups/adversaries/<ID>/victims/<ID>
    /<api version>/groups/emails/<ID>/victims/<ID>
    /<api version>/groups/incidents/<ID>/victims/<ID>
    /<api version>/groups/signatures/<ID>/victims/<ID>
    /<api version>/groups/threats/<ID>/victims/<ID>

    JSON Data:
    {"victim" : {
     "id" : 490,
     "name" : "Big Timmy",
     "description" : "Insider?",
     "org" : "Marketing",
     "suborg" : "Advertising",
     "workLocation" : "Arlington VA",
     "webLink" : "https://app.threatconnect.com/tc/auth/victim/victim.xhtml?victim=490"}
    """
    def __init__(self, http_method=PropertiesAction.GET):
        """ """
        super(VictimProperties, self).__init__(http_method)

        # resource properties
        self._resource_key = 'victim'
        self._resource_pagination = False
        self._resource_type = ResourceType.VICTIM
        self._resource_uri_attribute += '/%s'

    @property
    def id_owner_allowed(self):
        return False

    @property
    def id_path(self):
        return ResourceUri.VICTIMS.value + '/%s'

