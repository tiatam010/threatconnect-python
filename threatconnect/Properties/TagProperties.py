""" custom """
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.TagsProperties import TagsProperties


class TagProperties(TagsProperties):
    """
    URI:
    /<api version>/tags/<TAG NAME>

    JSON Data:
    {"name" : "32bit",
      "webLink" : "https://app.threatconnect.com/tc/auth/tags/
          tag.xhtml?tag=32bit&owner=Acme Corp"}
    """
    def __init__(self, base_uri='v2', http_method=PropertiesAction.GET):
        """ """
        super(TagProperties, self).__init__(base_uri, http_method)

        # resource properties
        self._resource_key = 'tag'
        self._resource_pagination = False
        self._resource_type = ResourceType.TAG
        self._resource_uri_attribute = 'tags'

    @property
    def name_owner_allowed(self):
        """ """
        return True

    @property
    def name_path(self):
        """ """
        return ResourceUri.TAGS.value + '/{0}'
