""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.Properties import Properties
from threatconnect.ResourceObject import resource_class


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
    def __init__(self, http_method=PropertiesAction.GET):
        """ """
        super(FileOccurrencesProperties, self).__init__(http_method)
        self._http_method = http_method

        # resource properties
        self._resource_key = 'fileOccurrence'
        self._resource_pagination = False
        self._resource_type = ResourceType.FILE_OCCURRENCES
        self._resource_uri_attribute = 'fileOccurrences'

        # object attributes
        self._object_attributes = [
            ResourceMethods.date_attr,
            ResourceMethods.file_name_attr,
            ResourceMethods.id_attr,
            ResourceMethods.path_attr]

        self._filter_methods = [
            'add_hash',
            'add_owner',
            'get_owners',
            'get_owner_allowed',
            'get_resource_pagination',
            'get_request_uri',
            'get_resource_type']

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

    @property
    def resource_object(self):
        return resource_class(self._object_attributes, self._http_method)()
