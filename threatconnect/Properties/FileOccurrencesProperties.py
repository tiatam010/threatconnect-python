""" custom """
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.Properties import Properties


class FileOccurrencesProperties(Properties):
    """
    URI:
    /v2/indicators/files/<hash>/fileOccurrences

    JSON Data:
    {"id" : 9722,
     "fileName" : "badguy.dll",
     "path" : "C:\\Windows\\System32",
     "date" : "2014-11-05T00:00:00Z"}

      {
    "resultCount" : 1,
    "fileOccurrence" : [ {
      "id" : 8771,
      "fileName" : "ts.dll",
      "path" : "",
      "date" : "2014-09-28T00:00:00Z"
    }
    """

    def __init__(self):
        """ """
        super(FileOccurrencesProperties, self).__init__()

        # resource properties
        self._resource_key = 'fileOccurrence'
        self._resource_pagination = False
        self._resource_type = ResourceType.FILE_OCCURRENCES
        self._resource_uri_attribute = 'fileOccurrences'

        self._data_methods = {
            'date': {
                'get': 'get_date',
                'set': 'set_date',
                'var': '_date'},
            'fileName': {
                'get': 'get_file_name',
                'set': 'set_file_name',
                'var': '_file_name'},
            'id': {
                'get': 'get_id',
                'set': 'set_id',
                'var': '_id'},
            'path': {
                'get': 'get_path',
                'set': 'set_path',
                'var': '_path'}}

        self._filter_methods = [
            'add_hash',
            'add_owner',
            'get_owners',
            'get_owner_allowed',
            'get_resource_pagination',
            'get_request_uri',
            'get_resource_type']

    @property
    def data_methods(self):
        """ """
        return self._data_methods

    @property
    def filters(self):
        """ """
        return self._filter_methods

    @property
    def hash_owner_allowed(self):
        """ """
        return True

    @property
    def hash_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/files/%s/' + self._resource_uri_attribute
