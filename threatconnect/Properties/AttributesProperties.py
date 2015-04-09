""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.Properties import Properties
from threatconnect.ResourceObject import resource_class


class AttributesProperties(Properties):
    """
    /<api version>/indicators/<INDICATOR TYPE>/<INDICATOR VALUE>/attributes
    /<api version>/groups/adversaries/<ID>/attributes
    /<api version>/groups/emails/<ID>/attributes
    /<api version>/groups/incidents/<ID>/attributes
    /<api version>/groups/signatures/<ID>/attributes
    /<api version>/groups/threats/<ID>/attributes

    JSON Data:
    {'id' : 4611990,
     'type' : 'Firewall implemented',
     'dateAdded' : '2015-03-20T13:50:08Z',
     'lastModified' : '2015-03-20T13:50:08Z',
     'displayed' : false,
     'value' : 'Actions on Objectives'}
    """
    def __init__(self, http_method=PropertiesAction.GET):
        """ """
        super(AttributesProperties, self).__init__()
        self._http_method = http_method

        # resource properties
        self._resource_key = 'attribute'
        self._resource_pagination = True
        self._resource_type = ResourceType.ATTRIBUTES
        self._resource_uri_attribute = 'attributes'

        self._object_attributes = [
            ResourceMethods.date_added_attr,
            ResourceMethods.displayed_attr,
            ResourceMethods.id_attr,
            ResourceMethods.last_modified_attr,
            ResourceMethods.matched_filters_attr,
            ResourceMethods.value_attr,
            ResourceMethods.type_attr]

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
    def delete_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/%s/%s/%s/%s'

    @property
    def email_owner_allowed(self):
        """ """
        return False

    @property
    def email_path(self):
        """ """
        return ResourceUri.EMAILS.value + '/%s/' + self._resource_uri_attribute

    # @property
    # def data_methods(self):
    #     return self._data_methods

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
    def post_path(self):
        """ """
        return ResourceUri.GROUPS.value + '/' + self._resource_uri_attribute

    @property
    def put_path(self):
        """ """
        return ResourceUri.GROUPS.value + '/%s/%s/%s/%s'

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

