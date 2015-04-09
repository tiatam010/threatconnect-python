""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.Properties import Properties
from threatconnect.ResourceObject import resource_class


class SecurityLabelsProperties(Properties):
    """
    URIs:
    /<api version>/securityLabels
    /<api version>/indicators/<INDICATOR TYPE>/<INDICATOR VALUE>/securityLabels
    /<api version>/groups/adversaries/<ID>/securityLabels
    /<api version>/groups/emails/<ID>/securityLabels
    /<api version>/groups/incidents/<ID>/securityLabels
    /<api version>/groups/signatures/<ID>/securityLabels
    /<api version>/groups/threats/<ID>/securityLabels

    JSON Data:
    {"name" : "DO NOT SHARE",
     "description" : "This data is ACME CONFIDENTIAL and is not approved for external release.",
     "dateAdded" : "2014-03-17T15:29:53Z"}
    """
    def __init__(self, http_method=PropertiesAction.GET):
        """ """
        super(SecurityLabelsProperties, self).__init__(http_method)
        self._http_method = http_method

        # resource properties
        self._resource_key = 'securityLabel'
        self._resource_pagination = True
        self._resource_type = ResourceType.SECURITY_LABELS
        self._resource_uri_attribute = 'securityLabels'

        # object attributes
        self._object_attributes = [
            ResourceMethods.date_added_attr,
            ResourceMethods.description_attr,
            ResourceMethods.matched_filters_attr,
            ResourceMethods.name_attr]

        # fileter methods
        self._filter_methods = [
            'add_adversary_id',
            'add_email_id',
            'add_incident_id',
            'add_indicator',
            'add_name',
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
        return True

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
        return '/v2/' + self._resource_uri_attribute

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
        return resource_class(self._object_attributes, self._resource_type, self._http_method)()

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
