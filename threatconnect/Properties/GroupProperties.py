""" custom """
from threatconnect.Properties.Properties import Properties


class GroupProperties(Properties):
    """ """
    def __init__(self):
        """ """
        super(GroupProperties, self).__init__()

        self._data_methods = {
            'dateAdded': {
                'get': 'get_date_added',
                'set': 'set_date_added',
                'var': '_date_added'},
            'id': {
                'get': 'get_id',
                'set': 'set_id',
                'var': '_id'},
            'name': {
                'get': 'get_name',
                'set': 'set_name',
                'var': '_name'},
            'ownerName': {
                'get': 'get_owner_name',
                'set': 'set_owner_name',
                'var': '_owner_name'},
            'type': {
                'get': 'get_type',
                'set': 'set_type',
                'var': '_type'},
            'webLink': {
                'get': 'get_web_link',
                'set': 'set_web_link',
                'var': '_web_link'}}

    @property
    def data_methods(self):
        """ """
        return self._data_methods

    # @property
    # def filters(self):
    #     """ """
    #     return self._filter_methods
