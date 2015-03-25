""" custom """
from threatconnect.Properties.Properties import Properties


class IndicatorProperties(Properties):
    """ """

    def __init__(self):
        """ """
        super(IndicatorProperties, self).__init__()

        self._data_methods = {
            'dateAdded': {
                'get': 'get_date_added',
                'set': 'set_date_added',
                'var': '_date_added'},
            'description': {
                'get': 'get_description',
                'set': 'set_description',
                'var': '_description'},
            'id': {
                'get': 'get_id',
                'set': 'set_id',
                'var': '_id'},
            'lastModified': {
                'get': 'get_last_modified',
                'set': 'set_last_modified',
                'var': '_last_modified'},
            'owner': {
                'get': 'get_owner_name',
                'set': 'set_owner',
                'var': '_owner_name'},
            'threatAssessConfidence': {
                'get': 'get_confidence',
                'set': 'set_confidence',
                'var': '_confidence'},
            'threatAssessRating': {
                'get': 'get_rating',
                'set': 'set_rating',
                'var': '_rating'},
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
