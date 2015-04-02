""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.Properties import Properties
from threatconnect.ResourceObject import resource_class


class IndicatorProperties(Properties):
    """ """

    def __init__(self, http_method=PropertiesAction.GET):
        """ """
        super(IndicatorProperties, self).__init__(http_method)
        self._http_method = http_method

        self._object_attributes = [
            ResourceMethods.confidence_attr,
            ResourceMethods.date_added_attr,
            ResourceMethods.description_attr,
            ResourceMethods.id_attr,
            ResourceMethods.last_modified_attr,
            ResourceMethods.owner_name_attr,
            ResourceMethods.matched_filters_attr,
            ResourceMethods.rating_attr,
            ResourceMethods.summary_attr,
            ResourceMethods.type_attr,
            ResourceMethods.web_link_attr,
        ]

    @property
    def delete_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/%s/%s'

    @property
    def post_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/' + self._resource_uri_attribute

    @property
    def put_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/%s/%s'

    @property
    def resource_object(self):
        # return self._resource_class()
        return resource_class(self._object_attributes, self._http_method)()
