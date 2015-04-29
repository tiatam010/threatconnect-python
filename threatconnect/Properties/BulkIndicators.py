""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.Properties import Properties
from threatconnect.ResourceObject import resource_class


class BulkProperties(Properties):
    """
    URIs:
    /<api version>/indicators/bulk?owner=<owner name>

    JSON Data:
    "bulkStatus" : {
      "name" : "Common Community",
      "csvEnabled" : true,
      "jsonEnabled" : true,
      "nextRun" : "2015-04-14T00:00:00Z",
      "lastRun" : "2015-04-13T00:01:14Z",
      "status" : "Complete"
    }
    """
    def __init__(self, base_uri='v2', http_method=PropertiesAction.GET):
        """ """
        super(BulkProperties, self).__init__(base_uri, http_method)
        self._http_method = http_method

        # resource properties
        self._resource_key = 'bulkStatus'
        self._resource_pagination = False
        self._resource_type = ResourceType.BULK
        self._resource_uri_attribute = 'bulk'

        self._object_attributes = [
            ResourceMethods.csv_enabled_attr,
            ResourceMethods.json_enabled_attr,
            ResourceMethods.last_run_attr,
            ResourceMethods.matched_filters_attr,
            ResourceMethods.name_attr,
            ResourceMethods.next_run_attr,
            ResourceMethods.status_attr]

        self._filter_methods = [
            'add_owner',
            'get_owners',
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
        return ResourceUri.INDICATORS.value + '/' + self._resource_uri_attribute

    @property
    def download_owner_allowed(self):
        """ """
        return True

    @property
    def download_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/' + self._resource_uri_attribute + '/download/{0}'

    @property
    def resource_object(self):
        return resource_class(self._object_attributes, self._resource_type)()
