""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.GroupProperties import GroupProperties


class EmailProperties(GroupProperties):
    """
    URIs:
    /<api version>/groups/emails/<ID>

    JSON Data:
    {"id" : 158758,
     "name" : "[spendbitcoins] Invoice Payment (#765293)",
     "owner" : {
       "id" : 689,
       "name" : "Subscriber Community",
       "type" : "Community"
     },
     "dateAdded" : "2014-12-05T23:11:05Z",
     "webLink" : "https://app.threatconnect.com/tc/auth/email/email.xhtml?email=158758",
     "to" : "",
     "from" : "support@spendbitcoins.orgs",
     "subject" : "[spendbitcoins] Invoice Payment (#765293)",
     "score" : 0,
     "header" : "Received: from mailer152.gate176.sl.smtp.com <truncted>'
     "body" : "INVOICE #765293\r\n\r\nSTATUS: Unpaid\r\n\r\n<truncated>'}
    """

    def __init__(self, action=PropertiesAction.READ):
        """ """
        super(EmailProperties, self).__init__(action)
        self._action = action

        # resource properties
        self._resource_key = 'email'
        self._resource_pagination = False
        self._resource_type = ResourceType.EMAIL
        self._resource_uri_attribute = 'emails'

        # update object attributes
        self._object_attributes.remove(ResourceMethods.type_attr)
        self._object_attributes.append(ResourceMethods.body_attr)
        self._object_attributes.append(ResourceMethods.from_attr)
        self._object_attributes.append(ResourceMethods.header_attr)
        self._object_attributes.append(ResourceMethods.score_attr)
        self._object_attributes.append(ResourceMethods.subject_attr)
        self._object_attributes.append(ResourceMethods.to_attr)

    @property
    def id_owner_allowed(self):
        """ """
        return False

    @property
    def id_path(self):
        """ """
        return ResourceUri.EMAILS.value + '/%s'
