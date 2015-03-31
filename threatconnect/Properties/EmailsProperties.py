""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Properties.GroupsProperties import GroupsProperties


class EmailsProperties(GroupsProperties):
    """
    URIs:
    /<api version>/groups/emails
    /<api version>/indicators/<indicator type>/<value>/groups/emails
    /<api version>/groups/adversaries/<ID>/groups/emails
    /<api version>/groups/incidents/<ID>/groups/emails
    /<api version>/groups/signatures/<ID>/groups/signatures
    /<api version>/groups/threats/<ID>/groups/emails
    /<api version>/securityLabels/<security label>/groups/emails
    /<api version>/tags/<tag name>/groups/emails
    /<api version>/victims/<ID>/groups/emails

    JSON Data:
    {"id" : 169256,
     "name" : "Click Me!",
     "ownerName" : "Acme Corp",
     "dateAdded" : "2014-12-11T18:44:22Z",
     "webLink" : "https://app.threatconnect.com/tc/auth/email/email.xhtml?email=169256",
     "score" : 300}
    """
    def __init__(self, action=PropertiesAction.READ):
        """ """
        super(EmailsProperties, self).__init__(action)

        # resource properties
        self._resource_key = 'email'
        self._resource_pagination = True
        self._resource_type = ResourceType.EMAILS
        self._resource_uri_attribute += '/emails'

        # update object attributes
        self._object_attributes.remove(ResourceMethods.type_attr)
        self._object_attributes.append(ResourceMethods.score_attr)

        # update filter methods
        self._filter_methods.remove('add_email_id')
        self._filter_methods.append('add_id')
