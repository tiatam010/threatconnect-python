""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Properties.Properties import Properties
from threatconnect.ResourceObject import resource_class


class IndicatorsProperties(Properties):
    """
    URIs:
    /<api version>/indicators
    /<api version>/groups/adversaries/<ID>/indicators
    /<api version>/groups/emails/<ID>/indicators
    /<api version>/groups/incidents/<ID>/indicators
    /<api version>/groups/signatures/<ID>/indicators
    /<api version>/groups/threats/<ID>/indicators
    /<api version>/securityLabels/<security label>/indicators
    /<api version>/tags/<tag name>/indicators
    /<api version>/victims/<ID>/indicators

    JSON Data:
    {'id' : 1740984,
     'ownerName' : 'Acme Corp',
     'type' : 'Address',
     'dateAdded' : '2015-03-12T16:32:02Z',
     'lastModified' : '2015-03-12T20:50:54Z',
     'rating' : 5.0,
     'confidence' : 23,
     'webLink' : 'https://app.threatconnect.com/tc/auth/indicators/
         details/setress.xhtml?setress=60.1.2.243&owner=Acme+Corp',
     'description' : 'Conducted exploits to retrieve administration
         credentials and used to extract card information.',
     'summary' : '60.1.2.243'}
    """
    def __init__(self, base_uri='v2', http_method=PropertiesAction.GET):
        """ """
        super(IndicatorsProperties, self).__init__(base_uri, http_method)

        # resource properties
        self._resource_key = 'indicator'
        self._resource_pagination = True
        self._resource_type = ResourceType.INDICATORS
        self._resource_uri_attribute = 'indicators'

        self._object_attributes = [
            ResourceMethods.confidence_attr,
            ResourceMethods.date_added_attr,
            ResourceMethods.description_attr,
            ResourceMethods.id_attr,
            ResourceMethods.indicator_attr,
            ResourceMethods.last_modified_attr,
            ResourceMethods.owner_name_attr,
            ResourceMethods.matched_filters_attr,
            ResourceMethods.rating_attr,
            ResourceMethods.threat_assess_confidence_attr,
            ResourceMethods.threat_assess_rating_attr,
            ResourceMethods.summary_attr,
            ResourceMethods.type_attr,
            ResourceMethods.web_link_attr]

    @property
    def base_owner_allowed(self):
        """ """
        return True

    @property
    def base_path(self):
        """ """
        return '/' + self._base_uri + '/' + self._resource_uri_attribute

    @property
    def adversary_owner_allowed(self):
        """ """
        return False

    @property
    def adversary_path(self):
        """ """
        return ResourceUri.ADVERSARIES.value + '/%s/' + self._resource_uri_attribute

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
        return [
            'add_adversary_id',
            'add_pf_date_added',
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

    # @property
    # def association_indicator_path(self):
    #     """ """
    #     return ResourceUri.INDICATORS.value + '/' + self.resource_uri_attribute + '/%s/indicators'

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
        return resource_class(self._object_attributes, self._resource_type)()

    @property
    def security_label_owner_allowed(self):
        return True

    @property
    def security_label_path(self):
        return ResourceUri.SECURITY_LABELS.value + '/%s/' + self._resource_uri_attribute

    @property
    def signature_owner_allowed(self):
        return True

    @property
    def signature_path(self):
        return ResourceUri.SIGNATURES.value + '/%s/' + self._resource_uri_attribute

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
        """ """
        return False

    @property
    def victim_path(self):
        """ """
        return ResourceUri.VICTIMS.value + '/%s/' + self._resource_uri_attribute
