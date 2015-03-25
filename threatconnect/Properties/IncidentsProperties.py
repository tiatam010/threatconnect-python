""" custom """
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Properties.GroupsProperties import GroupsProperties


class IncidentsProperties(GroupsProperties):
    """ """
    def __init__(self):
        """
        URIs:
        /<api version>/groups/incidents
        /<api version>/indicators/<indicator type>/<value>/groups/incidents
        /<api version>/groups/adversaries/<ID>/groups/incidents
        /<api version>/groups/emails/<ID>/groups/incidents
        /<api version>/groups/incidents/<ID>/groups/incidents
        /<api version>/groups/threats/<ID>/groups/incidents
        /<api version>/securityLabels/<security label>/groups/incidents
        /<api version>/tags/<tag name>/groups/incidents
        /<api version>/victims/<ID>/groups/incidents

        JSON Data:
        {"id" : 120133,
         "name" : "20140415A: MLH Resume 2014 APT",
         "ownerName" : "Acme Corp",
         "dateAdded" : "2014-08-13T13:25:58Z",
         "webLink" : "https://app.threatconnect.com/tc/auth/incident/
             incident.xhtml?incident=120133",
         "eventDate" : "2014-04-15T00:00:00Z"}
        """
        super(IncidentsProperties, self).__init__()

        # resource properties
        self._resource_key = 'incident'
        self._resource_pagination = True
        self._resource_type = ResourceType.INCIDENTS
        self._resource_uri_attribute += '/incidents'

        # data methods
        self._data_methods.pop('type')

        # update filter methods
        self._filter_methods.remove('add_adversary_id')
        self._filter_methods.append('add_id')
