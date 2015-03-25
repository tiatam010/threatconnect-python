""" custom """
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.Properties import Properties


class VictimsProperties(Properties):
    """
    URIs:
    /<api version>/victims
    /<api version>/indicators/<INDICATOR TYPE>/<INDICATOR VALUE>/victims
    /<api version>/groups/adversaries/<ID>/victims
    /<api version>/groups/emails/<ID>/victims
    /<api version>/groups/incidents/<ID>/victims
    /<api version>/groups/signatures/<ID>/victims
    /<api version>/groups/threats/<ID>/victims

    JSON Data:
    {"id" : 386,
     "name" : "Atlanta Office",
     "org" : "Acme Corp",
     "suborg" : "HR",
     "nationality" : "US",
     "workLocation" : "Arlington VA",
     "webLink" : "https://app.threatconnect.com/tc/auth/victim/victim.xhtml?victim=386"}
    """

    def __init__(self):
        """ """
        super(VictimsProperties, self).__init__()

        # resource properties
        self._resource_key = 'victim'
        self._resource_pagination = True
        self._resource_type = ResourceType.VICTIMS
        self._resource_uri_attribute = 'victims'

        # data methods
        self._data_methods = {
            'id': {
                'get': 'get_id',
                'set': 'set_id',
                'var': '_id'},
            'name': {
                'get': 'get_name',
                'set': 'set_name',
                'var': '_name'},
            'nationality': {
                'get': 'get_nationality',
                'set': 'set_nationality',
                'var': '_nationality'},
            'org': {
                'get': 'get_org',
                'set': 'set_org',
                'var': '_org'},
            'suborg': {
                'get': 'get_suborg',
                'set': 'set_suborg',
                'var': '_suborg'},
            'webLink': {
                'get': 'get_web_link',
                'set': 'set_web_link',
                'var': '_web_link'},
            'workLocation': {
                'get': 'get_work_location',
                'set': 'set_work_location',
                'var': '_work_location'}}

        self._filter_methods = [
            'add_adversary_id',
            'add_email_id',
            'add_id',
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
    def base_owner_allowed(self):
        """ """
        return True

    @property
    def base_path(self):
        """ """
        return '/v2/' + self._resource_uri_attribute

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
        """ """
        return self._data_methods

    @property
    def filters(self):
        """ """
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
