""" custom """
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.Properties import Properties


class DnsResolutionProperties(Properties):
    """
    URI:
    /<api version>/indicators/hosts/<hostname>/dnsResolutions

    JSON Data:
    {'resolutionDate' : '2015-02-18T19:03:05Z',
     'addresses' : [ {
         'ownerName' : 'Acme Corp',
         'dateAdded' : null,
         'lastModified' : null,
         'webLink' : 'https://app.threatconnect.com/tc/auth/indicators/details/
             address.xhtml?address=62.76.47.24&owner=Acme Corp',
         'ip' : '62.76.47.24'}
    """

    def __init__(self, base_uri='v2', http_method=PropertiesAction.GET):
        """ """
        super(DnsResolutionProperties, self).__init__(base_uri, http_method)

        # resource properties
        self._resource_key = 'dnsResolution'
        self._resource_pagination = False
        self._resource_type = ResourceType.DNS_RESOLUTIONS
        self._resource_uri_attribute = 'dnsResolutions'

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
            'add_indicator']


@property
def base_owner_allowed(self):
    """ """
    return True


@property
def base_path(self):
    """ """
    return ResourceUri.INDICATORS.value + '/host/%s/' + self._resource_uri_attribute
