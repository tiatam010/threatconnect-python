""" custom """
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Properties.IndicatorsProperties import IndicatorsProperties


class FilesProperties(IndicatorsProperties):
    """
    URIs:
    /<api version>/indicators/files
    /<api version>/groups/adversaries/<ID>/indicators/files
    /<api version>/groups/emails/<ID>/indicators/files
    /<api version>/groups/incidents/<ID>/indicators/files
    /<api version>/groups/signatures/<ID>/indicators/files
    /<api version>/groups/threats/<ID>/indicators/files
    /<api version>/securityLabels/<security label>/indicators/files
    /<api version>/tags/<tag name>/indicators/files
    /<api version>/victims/<ID>/indicators/files

    JSON Data:
    {"id" : 1526418,
     "ownerName" : "Acme Corp",
     "dateAdded" : "2015-02-12T19:03:54Z",
     "lastModified" : "2015-02-12T19:03:54Z",
     "rating" : 3.0,
     "confidence" : 61,
     "threatAssessRating" : 4.6,
     "threatAssessConfidence" : 100.0,
     "webLink" : "https://app.threatconnect.com/tc/auth/indicators/
         details/file.xhtml?file=8849538EF1C3471640230605C2623C67&owner=Acme+Corp",
     "description" : "Indicators from SpearPhish Email 1/12/2015",
     "md5" : "8849538EF1C3471640230605C2623C67"
    }

    """
    def __init__(self):
        """ """
        super(FilesProperties, self).__init__()

        # resource properties
        self._resource_key = 'file'
        self._resource_pagination = True
        self._resource_type = ResourceType.FILES
        self._resource_uri_attribute += '/files'

        # update data methods
        self._data_methods.pop('summary')
        self._data_methods['md5'] = {
            'get': 'get_indicator',
            'set': 'set_hash',
            'var': '_indicator'}
        self._data_methods['sha1'] = {
            'get': 'get_indicator',
            'set': 'set_hash',
            'var': '_indicator'}
        self._data_methods['sha256'] = {
            'get': 'get_indicator',
            'set': 'set_hash',
            'var': '_indicator'}
