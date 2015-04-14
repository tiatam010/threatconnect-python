""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Properties.Properties import Properties
from threatconnect.ResourceObject import resource_class


class BulkIndicatorsProperties(Properties):
    """
    URIs:
    /<api version>/indicators/bulk/csv?owner=<owner name>
    /<api version>/indicators/bulk/json?owner=<owner name>

    "indicator" : [ {
      "id" : 73011,
      "ownerName" : "Common Community",
      "type" : "Address",
      "dateAdded" : "2013-07-27T22:14:56Z",
      "lastModified" : "2013-07-27T22:14:56Z",
      "rating" : 4.0,
      "confidence" : 100,
      "threatAssessRating" : 4.02,
      "threatAssessConfidence" : 99.71,
      "webLink" : "https://app.threatconnect.com/tc/auth/indicators/details/address.xhtml?address=180.210.204.227&owner=Common+Community",
      "description" : "C&C Server used by digitally signed APT from Bit9 compromise. APT is Mdmbot / Naid Trojan.",
      "summary" : "180.210.204.227",
      "attribute" : [ {
        "id" : 132260,
        "type" : "Source",
        "dateAdded" : "2013-07-27T22:14:56Z",
        "lastModified" : "2013-09-18T21:42:28Z",
        "displayed" : true,
        "value" : "http://krebsonsecurity.com/2013/02/bit9-breach-began-in-july-2012/"
      }
      <snip>
      "tag" : [ {
        "name" : "Advanced Persistent Threat",
        "webLink" : "https://app.threatconnect.com/tc/auth/tags/tag.xhtml?tag=Advanced Persistent Threat&owner=Common Community"
      }, {
        "name" : "China",
        "webLink" : "https://app.threatconnect.com/tc/auth/tags/tag.xhtml?tag=China&owner=Common Community"
      },
    <snip>
    """
    def __init__(self, base_uri='v2', http_method=PropertiesAction.GET):
        """ """
        super(BulkIndicatorsProperties, self).__init__(base_uri, http_method)

        # resource properties
        self._resource_key = 'indicator'
        self._resource_pagination = False
        self._resource_type = ResourceType.INDICATORS
        self._resource_uri_attribute = 'bulk'

        self._object_attributes = [
            ResourceMethods.confidence_attr,
            ResourceMethods.date_added_attr,
            ResourceMethods.description_attr,
            ResourceMethods.id_attr,
            ResourceMethods.last_modified_attr,
            ResourceMethods.owner_name_attr,
            ResourceMethods.matched_filters_attr,
            ResourceMethods.rating_attr,
            ResourceMethods.threat_assess_confidence_attr,
            ResourceMethods.threat_assess_rating_attr,
            ResourceMethods.summary_attr,
            ResourceMethods.type_attr,
            ResourceMethods.web_link_attr]

        self._filter_methods = [
            'add_attribute',  # Post Filter
            'add_confidence',  # Post Filter
            'add_date_added',  # Post Filter
            'add_last_modified',  # Post Filter
            'add_owner',
            'add_rating',  # Post Filter
            'add_tag',  # Post Filter
            'add_threat_assess_confidence',  # Post Filter
            'add_threat_assess_rating',  # Post Filter
            'add_type',  # Post Filter
            'get_owners',
            'get_owner_allowed',
            'get_resource_pagination',
            'get_request_uri',
            'get_resource_type',
            'set_format']

    @property
    def base_owner_allowed(self):
        """ """
        return True

    @property
    def base_path(self):
        """ """
        return '/' + self._base_uri + '/indicators/' + self._resource_uri_attribute + '/%s'

    @property
    def filters(self):
        """ """
        return self._filter_methods

    @property
    def resource_object(self):
        return resource_class(self._object_attributes, self._resource_type, self._http_method)()
