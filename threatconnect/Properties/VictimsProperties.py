""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.Properties import Properties
from threatconnect.ResourceObject import resource_class


class VictimsProperties(Properties):
    """
    URIs:
    /<api version>/victims
    /<api version>/indicators/<INDICATOR TYPE>/<INDICATOR VALUE>/victims
    /<api version>/groups/adversaries/<ID>/victims
    /<api version>/groups/emails/<ID>/victims
    /<api version>/groups/incidents/<ID>/victims
    /<api version>/groups/signatures/<ID>/victims
    /<api version>/groups/threats/<ID>/victims

    JSON Data:
    {"id" : 386,
     "name" : "Atlanta Office",
     "org" : "Acme Corp",
     "suborg" : "HR",
     "nationality" : "US",
     "workLocation" : "Arlington VA",
     "webLink" : "https://app.threatconnect.com/tc/auth/victim/victim.xhtml?victim=386"}
    """
    def __init__(self, base_uri='v2', http_method=PropertiesAction.GET):
        """ """
        super(VictimsProperties, self).__init__(base_uri, http_method)
        self._http_method = http_method

        # resource properties
        self._resource_key = 'victim'
        self._resource_pagination = True
        self._resource_type = ResourceType.VICTIMS
        self._resource_uri_attribute = 'victims'

        # object attributes
        self._object_attributes = [
            ResourceMethods.id_attr,
            ResourceMethods.matched_filters_attr,
            ResourceMethods.name_attr,
            ResourceMethods.nationality_attr,
            ResourceMethods.org_attr,
            ResourceMethods.suborg_attr,
            ResourceMethods.work_location_attr,
            ResourceMethods.web_link_attr]

        self._filter_methods = [
            'add_adversary_id',
            'add_email_id',
            'add_id',
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
        return ResourceUri.ADVERSARIES.value + '/{0}/' + self._resource_uri_attribute

    @property
    def base_owner_allowed(self):
        """ """
        return True

    @property
    def base_path(self):
        """ """
        return '/' + self._base_uri + '/' + self._resource_uri_attribute

    @property
    def delete_path(self):
        """ """
        return ResourceUri.VICTIMS.value + '/{0}'

    @property
    def email_owner_allowed(self):
        """ """
        return False

    @property
    def email_path(self):
        """ """
        return ResourceUri.EMAILS.value + '/{0}/' + self._resource_uri_attribute

    @property
    def filters(self):
        """ """
        return self._filter_methods

    @property
    def incident_owner_allowed(self):
        return False

    @property
    def incident_path(self):
        return ResourceUri.INCIDENTS.value + '/{0}/' + self._resource_uri_attribute

    @property
    def indicator_owner_allowed(self):
        return True

    @property
    def indicator_path(self):
        return ResourceUri.INDICATORS.value + '/{0}/{1}/' + self._resource_uri_attribute

    @property
    def post_path(self):
        """ """
        return ResourceUri.VICTIMS.value

    @property
    def put_path(self):
        """ """
        return ResourceUri.VICTIMS.value + '/{0}'

    @property
    def resource_object(self):
        return resource_class(self._object_attributes, self._resource_type)()

    @property
    def signature_owner_allowed(self):
        return False

    @property
    def signature_path(self):
        return ResourceUri.SIGNATURES.value + '/{0}/' + self._resource_uri_attribute

    @property
    def threat_owner_allowed(self):
        return False

    @property
    def threat_path(self):
        return ResourceUri.THREATS.value + '/{0}/' + self._resource_uri_attribute
