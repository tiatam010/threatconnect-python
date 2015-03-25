""" custom """
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.Properties import Properties


class OwnersProperties(Properties):
    """
    URIs:
    /v2/owners
    /v2/indicators/<indicator type>/<value>/owners

    JSON Data:
    {"id" : 640,
     "name" : "Demo Customer Community",
     "type" : "Community"
    }
    """

    def __init__(self):
        """
        /<api version>/owners
        /<api version>/indicators/<indicator type>/<value>/owners
        """
        super(OwnersProperties, self).__init__()

        # resource properties
        self._resource_key = 'owner'
        self._resource_pagination = False
        self._resource_type = ResourceType.OWNERS
        self._resource_uri_attribute = 'owners'

    @property
    def base_owner_allowed(self):
        """ """
        return False

    @property
    def base_path(self):
        """ """
        return ResourceUri.OWNERS.value

    @property
    def data_methods(self):
        """ """
        return {
            'id': {
                'get': 'get_id',
                'set': 'set_id',
                'var': '_id'},
            'name': {
                'get': 'get_name',
                'set': 'set_name',
                'var': '_name'},
            'type': {
                'get': 'get_type',
                'set': 'set_type',
                'var': '_type'}}

    @property
    def filters(self):
        """ """
        return [
            'add_indicator']

    @property
    def indicator_owner_allowed(self):
        return False

    @property
    def indicator_path(self):
        return ResourceUri.INDICATORS.value + '/%s/%s/' + self._resource_uri_attribute
