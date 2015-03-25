""" custom """
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.Properties import Properties


class AttributesProperties(Properties):
    """
    /<api version>/indicators/<INDICATOR TYPE>/<INDICATOR VALUE>/attributes
    /<api version>/groups/adversaries/<ID>/attributes
    /<api version>/groups/emails/<ID>/attributes
    /<api version>/groups/incidents/<ID>/attributes
    /<api version>/groups/signatures/<ID>/attributes
    /<api version>/groups/threats/<ID>/attributes

    JSON Data:
    {'id' : 4611990,
     'type' : 'Firewall implemented',
     'dateAdded' : '2015-03-20T13:50:08Z',
     'lastModified' : '2015-03-20T13:50:08Z',
     'displayed' : false,
     'value' : 'Actions on Objectives'}
    """

    def __init__(self):
        """ """
        super(AttributesProperties, self).__init__()

        # resource properties
        self._resource_key = 'attribute'
        self._resource_pagination = True
        self._resource_type = ResourceType.ATTRIBUTES
        self._resource_uri_attribute = 'attributes'

        self._data_methods = {
            'dateAdded': {
                'get': 'get_date_added',
                'set': 'set_date_added',
                'var': '_date_added'},
            'displayed': {
                'get': 'get_displayed',
                'set': 'set_displayed',
                'var': '_displayed'},
            'id': {
                'get': 'get_id',
                'set': 'set_id',
                'var': '_id'},
            'lastModified': {
                'get': 'get_last_modified',
                'set': 'set_last_modified',
                'var': '_last_modified'},
            'type': {
                'get': 'get_type',
                'set': 'set_type',
                'var': '_type'}}

        self._filter_methods = [
            'add_adversary_id',
            'add_email_id',
            'add_incident_id',
            'add_indicator',
            'add_owner',
            'add_signature_id',
            'add_threat_id',
            'get_owners',
            'get_owner_allowed',
            'get_resource_pagination',
            'get_request_uri',
            'get_resource_type']

    @property
    def adversary_owner_allowed(self):
        """ """
        return False

    @property
    def adversary_path(self):
        """ """
        return ResourceUri.ADVERSARIES.value + '/%s/' + self._resource_uri_attribute

    @property
    def email_owner_allowed(self):
        """ """
        return False

    @property
    def email_path(self):
        """ """
        return ResourceUri.EMAILS.value + '/%s/' + self._resource_uri_attribute

    @property
    def data_methods(self):
        return self._data_methods

    @property
    def filters(self):
        return self._filter_methods

    @property
    def incident_owner_allowed(self):
        return False

    @property
    def incident_path(self):
        return ResourceUri.INCIDENTS.value + '/%s/' + self._resource_uri_attribute

    @property
    def indicator_owner_allowed(self):
        return True

    @property
    def indicator_path(self):
        return ResourceUri.INDICATORS.value + '/%s/%s/' + self._resource_uri_attribute

    @property
    def signature_owner_allowed(self):
        return False

    @property
    def signature_path(self):
        return ResourceUri.SIGNATURES.value + '/%s/' + self._resource_uri_attribute

    @property
    def threat_owner_allowed(self):
        return False

    @property
    def threat_path(self):
        return ResourceUri.THREATS.value + '/%s/' + self._resource_uri_attribute
