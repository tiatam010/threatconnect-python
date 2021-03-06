""" custom """
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Properties.FileOccurrencesProperties import FileOccurrencesProperties


class FileOccurrenceProperties(FileOccurrencesProperties):
    """
    URI:
    /v2/indicators/files/<hash>/fileOccurrences

    JSON Data:
    {"fileOccurrence" : {
      "id" : 8771,
      "fileName" : "ts.dll",
      "path" : "",
      "date" : "2014-09-28T00:00:00Z"}
    """

    def __init__(self, base_uri='v2', http_method=PropertiesAction.GET):
        """ """
        super(FileOccurrenceProperties, self).__init__(base_uri, http_method)

        # resource properties
        self._resource_key = 'fileOccurrence'
        self._resource_pagination = False
        self._resource_type = ResourceType.FILE_OCCURRENCE
        self._resource_uri_attribute += '/{0}'

