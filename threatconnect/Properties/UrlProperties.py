""" custom """
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.IndicatorProperties import IndicatorProperties


class UrlProperties(IndicatorProperties):
    """
    URI:
    /<api version>/indicators/urls/<INDICATOR VALUE>

    JSON Data:
    {"id" : 1658560,
     "owner" : {
       "id" : 665,
       "name" : "Acme Corp",
       "type" : "Organization"
     },
     "dateAdded" : "2015-03-06T18:38:46Z",
     "lastModified" : "2015-03-06T18:38:46Z",
     "rating" : 1.0,
     "confidence" : 100,
     "webLink" : "https://app.threatconnect.com/tc/auth/indicators/
          details/url.xhtml?orgid=1658560",
     "source" : "ThreatConnect Intelligence Research Team Enrichment",
     "description" : "Faux virus tech support scam page location.
         Associated with the phone number 1-888-996-0235",
     "text" : "http://warning4.media4.netdna-cdn.com/lpbrowser_1_6_mac/"}
    """

    def __init__(self):
        """ """
        super(UrlProperties, self).__init__()

        # resource properties
        self._resource_key = 'url'
        self._resource_pagination = False
        self._resource_type = ResourceType.URL
        self._resource_uri_attribute = 'urls'

        # update data methods
        self._data_methods['source'] = {
            'get': 'get_source',
            'set': 'set_source',
            'var': '_source'}
        self._data_methods['text'] = {
            'get': 'get_indicator',
            'set': 'set_text',
            'var': '_indicator'}

    @property
    def indicator_owner_allowed(self):
        """ """
        return False

    @property
    def indicator_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/%s/%s'
