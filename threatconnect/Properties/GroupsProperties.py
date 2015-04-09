""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.Properties import Properties
from threatconnect.ResourceObject import resource_class


class GroupsProperties(Properties):
    """
    URIs:
    /<api version>/groups
    /<api version>/indicators/<indicator type>/<value>/groups
    /<api version>/groups/adversaries/<ID>/groups
    /<api version>/groups/emails/<ID>/groups
    /<api version>/groups/incidents/<ID>/groups
    /<api version>/groups/threats/<ID>/groups
    /<api version>/securityLabels/<security label>/groups
    /<api version>/tags/<tag name>/groups
    /<api version>/victims/<ID>/groups

    JSON Data:
    {"id" : 64571,
     "name" : "Bad Guy",
     "type" : "Adversary",
     "ownerName" : "Acme Corp",
     "dateAdded" : "2014-03-12T15:11:32Z",
     "webLink" : "https://app.threatconnect.com/tc/auth/adversary/
         adversary.xhtml?adversary=64571"}
    """
    def __init__(self, http_method=PropertiesAction.GET):
        """ """
        super(GroupsProperties, self).__init__(http_method)
        self._http_method = http_method

        # resource properties
        self._resource_key = 'group'
        self._resource_pagination = True
        self._resource_type = ResourceType.GROUPS
        self._resource_uri_attribute = 'groups'

        self._object_attributes = [
            ResourceMethods.date_added_attr,
            ResourceMethods.id_attr,
            ResourceMethods.matched_filters_attr,
            ResourceMethods.name_attr,
            ResourceMethods.owner_name_attr,
            ResourceMethods.type_attr,
            ResourceMethods.web_link_attr]

        self._filter_methods = [
            'add_adversary_id',
            'add_date_added',
            'add_email_id',
            'add_incident_id',
            'add_indicator',
            'add_owner',
            'add_security_label',
            'add_signature_id',
            'add_threat_id',
            'add_tag',
            'add_victim_id',
            'get_owners',
            'get_owner_allowed',
            'get_resource_pagination',
            'get_request_uri',
            'get_resource_type']

    @property
    def base_owner_allowed(self):
        """ """
        return True

    @property
    def base_path(self):
        """ """
        return '/v2/' + self._resource_uri_attribute

    @property
    def adversary_owner_allowed(self):
        """ """
        return False

    @property
    def adversary_path(self):
        """ """
        return ResourceUri.ADVERSARIES.value + '/%s/' + self._resource_uri_attribute

    # @property
    # def data_methods(self):
    #     """ """
    #     return self._data_methods

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
        # return resource_class(self._object_attributes, self._http_method)()
        return resource_class(self._object_attributes, self._resource_type, self._http_method)()

    @property
    def signature_owner_allowed(self):
        return True

    @property
    def signature_path(self):
        return ResourceUri.SIGNATURES.value + '/%s/' + self._resource_uri_attribute

    @property
    def security_label_owner_allowed(self):
        return True

    @property
    def security_label_path(self):
        return ResourceUri.SECURITY_LABELS.value + '/%s/' + self._resource_uri_attribute

    @property
    def tag_owner_allowed(self):
        return True

    @property
    def tag_path(self):
        return ResourceUri.TAGS.value + '/%s/' + self._resource_uri_attribute

    @property
    def threat_owner_allowed(self):
        return False

    @property
    def threat_path(self):
        return ResourceUri.THREATS.value + '/%s/' + self._resource_uri_attribute

    @property
    def victim_owner_allowed(self):
        return False

    @property
    def victim_path(self):
        return ResourceUri.VICTIMS.value + '/%s/' + self._resource_uri_attribute
