""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.Properties import Properties
from threatconnect.ResourceObject import resource_class


class TagsProperties(Properties):
    """
    URIs:
    /<api version>/tags
    /<api version>/indicators/<INDICATOR TYPE>/<INDICATOR VALUE>/tags
    /<api version>/groups/adversaries/<ID>/tags
    /<api version>/groups/emails/<ID>/tags
    /<api version>/groups/incidents/<ID>/tags
    /<api version>/groups/signatures/<ID>/tags
    /<api version>/groups/threats/<ID>/tags

    JSON Data:
    {"name" : "32bit",
     "webLink" : "https://app.threatconnect.com/tc/auth/tags/
         tag.xhtml?tag=32bit&owner=Acme Corp"}
    """
    def __init__(self, http_method=PropertiesAction.GET):
        """ """
        super(TagsProperties, self).__init__(http_method)
        self._http_method = http_method

        # resource properties
        self._resource_key = 'tag'
        self._resource_pagination = True
        self._resource_type = ResourceType.TAGS
        self._resource_uri_attribute = 'tags'

        # object attributes
        self._object_attributes = [
            ResourceMethods.matched_filters_attr,
            ResourceMethods.name_attr,
            ResourceMethods.web_link_attr]

        # filter methods
        self._filter_methods = [
            'add_adversary_id',
            'add_email_id',
            'add_incident_id',
            'add_indicator',
            'add_owner',
            'add_signature_id',
            'add_threat_id',
            'get_owners',
            'get_owner_allowed',
            'get_resource_pagination',
            'get_request_uri',
            'get_resource_type']

    @property
    def adversary_owner_allowed(self):
        """ """
        return False

    @property
    def adversary_path(self):
        """ """
        return ResourceUri.ADVERSARIES.value + '/%s/' + self._resource_uri_attribute

    @property
    def base_owner_allowed(self):
        """ """
        return True

    @property
    def base_path(self):
        """ """
        return ResourceUri.TAGS.value

    @property
    def email_owner_allowed(self):
        """ """
        return False

    @property
    def email_path(self):
        """ """
        return ResourceUri.EMAILS.value + '/%s/' + self._resource_uri_attribute

    @property
    def filters(self):
        """ """
        return self._filter_methods

    @property
    def incident_owner_allowed(self):
        return False

    @property
    def incident_path(self):
        return ResourceUri.INCIDENTS.value + '/%s/' + self._resource_uri_attribute

    @property
    def indicator_owner_allowed(self):
        return True

    @property
    def indicator_path(self):
        return ResourceUri.INDICATORS.value + '/%s/%s/' + self._resource_uri_attribute

    @property
    def resource_object(self):
        return resource_class(self._object_attributes, self._http_method)()

    @property
    def signature_owner_allowed(self):
        return False

    @property
    def signature_path(self):
        return ResourceUri.SIGNATURES.value + '/%s/' + self._resource_uri_attribute

    @property
    def threat_owner_allowed(self):
        return False

    @property
    def threat_path(self):
        return ResourceUri.THREATS.value + '/%s/' + self._resource_uri_attribute
