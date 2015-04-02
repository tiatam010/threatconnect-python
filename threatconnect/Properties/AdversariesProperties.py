""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Properties.GroupsProperties import GroupsProperties
from threatconnect.Config.ResourceType import ResourceType


class AdversariesProperties(GroupsProperties):
    """
    URIs:
    /<api version>/groups/adversaries
    /<api version>/indicators/<indicator type>/<value>/groups/adversaries
    /<api version>/groups/emails/<ID>/groups/adversaries
    /<api version>/groups/incidents/<ID>/groups/adversaries
    /<api version>/groups/signatures/<ID>/groups/signatures
    /<api version>/groups/threats/<ID>/groups/adversaries
    /<api version>/securityLabels/<security label>/groups/adversaries
    /<api version>/tags/<tag name>/groups/adversaries
    /<api version>/victims/<ID>/groups/adversaries

    JSON Data:
    {"id" : 47328,
     "name" : "Adversary Name",
     "ownerName" : "Acme Corp",
     "dateAdded" : "2013-12-17T21:33:58Z",
     "webLink" : "https://app.threatconnect.com/tc/auth/adversary/
         adversary.xhtml?adversary=47328"}
    """
    def __init__(self, http_method=PropertiesAction.GET):
        """ """
        super(AdversariesProperties, self).__init__(http_method)

        # resource properties
        self._resource_key = 'adversary'
        self._resource_pagination = True
        self._resource_type = ResourceType.ADVERSARIES
        self._resource_uri_attribute += '/adversaries'

        # update object attributes
        self._object_attributes.remove(ResourceMethods.type_attr)

        # update filter methods
        self._filter_methods.remove('add_adversary_id')
        self._filter_methods.append('add_id')
