""" custom """
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

    def __init__(self):
        """ """
        super(EmailProperties, self).__init__()

        # resource properties
        self._resource_key = 'email'
        self._resource_pagination = False
        self._resource_type = ResourceType.EMAIL
        self._resource_uri_attribute = 'emails'

        # update data methods
        self._data_methods.pop('ownerName')
        self._data_methods.pop('type')
        self._data_methods['body'] = {
            'get': 'get_body',
            'set': 'set_body',
            'var': '_body'}
        self._data_methods['from'] = {
            'get': 'get_from',
            'set': 'set_from',
            'var': '_from'}
        self._data_methods['header'] = {
            'get': 'get_header',
            'set': 'set_header',
            'var': '_header'}
        self._data_methods['owner'] = {
            'get': 'get_owner_name',
            'set': 'set_owner',
            'var': '_owner_name'}
        self._data_methods['score'] = {
            'get': 'get_score',
            'set': 'set_score',
            'var': '_score'}
        self._data_methods['subject'] = {
            'get': 'get_subject',
            'set': 'set_subject',
            'var': '_subject'}
        self._data_methods['to'] = {
            'get': 'get_to',
            'set': 'set_to',
            'var': '_to'}

    @property
    def id_owner_allowed(self):
        """ """
        return False

    @property
    def id_path(self):
        """ """
        return ResourceUri.EMAILS.value + '/%s'
