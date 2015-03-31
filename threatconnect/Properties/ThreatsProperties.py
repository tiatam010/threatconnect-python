""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Properties.GroupsProperties import GroupsProperties


class ThreatsProperties(GroupsProperties):
    """
    URIs:
    /<api version>/groups/threats
    /<api version>/indicators/<indicator type>/<value>/groups/threats
    /<api version>/groups/adversaries/<ID>/groups/threats
    /<api version>/groups/emails/<ID>/groups/threats
    /<api version>/groups/incidents/<ID>/groups/threats
    /<api version>/groups/signatures/<ID>/groups/threats
    /<api version>/securityLabels/<security label>/groups/threats
    /<api version>/tags/<tag name>/groups/threats
    /<api version>/victims/<ID>/groups/threats

    JSON Data:
    {"id" : 63359,
     "name" : "2104-03-05:Threat",
     "ownerName" : "Acme Corp",
     "dateAdded" : "2014-03-05T13:19:57Z",
     "webLink" : "https://app.threatconnect.com/tc/auth/threat/
         threat.xhtml?threat=63359"}
    """
    def __init__(self, action=PropertiesAction.READ):
        """ """
        super(ThreatsProperties, self).__init__(action)

        # resource properties
        self._resource_key = 'threat'
        self._resource_pagination = True
        self._resource_type = ResourceType.THREATS
        self._resource_uri_attribute += '/threats'

        # update object attributes
        self._object_attributes.remove(ResourceMethods.type_attr)

        # update filter methods
        self._filter_methods.remove('add_threat_id')
        self._filter_methods.append('add_id')
