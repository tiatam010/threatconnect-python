""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Properties.IndicatorsProperties import IndicatorsProperties


class UrlsProperties(IndicatorsProperties):
    """
    URIs:
    /<api version>/indicators/urls
    /<api version>/groups/adversaries/<ID>/indicators/urls
    /<api version>/groups/emails/<ID>/indicators/urls
    /<api version>/groups/incidents/<ID>/indicators/urls
    /<api version>/groups/signatures/<ID>/indicators/urls
    /<api version>/groups/threats/<ID>/indicators/urls
    /<api version>/securityLabels/<security label>/indicators/urls
    /<api version>/tags/<tag name>/indicators/urls
    /<api version>/victims/<ID>/indicators/urls

    JSON Data:
    {"id" : 1658560,
     "ownerName" : "Acme Corp",
     "dateAdded" : "2015-03-06T18:38:46Z",
     "lastModified" : "2015-03-06T18:38:46Z",
     "rating" : 1.0,
     "confidence" : 100,
     "webLink" : "https://app.threatconnect.com/tc/auth/indicators/
         details/url.xhtml?orgid=1658560",
     "description" : "Faux virus tech support scam page location.
         Associated with the phone number 1-888-996-0235",
     "text" : "http://warning4.media4.netdna-cdn.com/lpbrowser_1_6_mac/"}
    """
    def __init__(self, http_method=PropertiesAction.GET):
        """ """
        super(UrlsProperties, self).__init__(http_method)

        # resource properties
        self._resource_key = 'url'
        self._resource_pagination = True
        self._resource_type = ResourceType.URLS
        self._resource_uri_attribute += '/urls'

        # update object attributes
        self._object_attributes.remove(ResourceMethods.summary_attr)
        self._object_attributes.append(ResourceMethods.text_attr)

