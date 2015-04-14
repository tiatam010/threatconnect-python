""" standard """
import types

""" custom """
from threatconnect import FilterMethods
from threatconnect.Config.IndicatorType import IndicatorType
from threatconnect.Config.ResourceProperties import ResourceProperties
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.FilterObject import FilterObject
from threatconnect.Properties.BulkIndicatorsProperties import BulkIndicatorsProperties
from threatconnect.RequestObject import RequestObject
from threatconnect.Resource import Resource

""" Note: PEP 8 intentionally ignored for variable/methods to match API standard. """


class BulkIndicators(Resource):
    """ """

    def __init__(self, tc_obj):
        """ """
        super(BulkIndicators, self).__init__(tc_obj)
        self._filter_class = BulkIndicatorFilterObject
        self._modified_since = None

        # set properties
        properties = BulkIndicatorsProperties(base_uri=self.base_uri)
        self._resource_type = properties.resource_type

        # create default request object for non-filtered requests
        self._request_object = RequestObject('bulk_indicators', 'default')
        self._request_object.set_http_method(properties.http_method)
        self._request_object.set_owner_allowed(properties.base_owner_allowed)
        self._request_object.set_request_uri(properties.base_path)
        self._request_object.set_resource_pagination(properties.resource_pagination)
        self._request_object.set_resource_type(properties.resource_type)


class BulkIndicatorFilterObject(FilterObject):
    """ """

    def __init__(self, base_uri):
        """ """
        super(BulkIndicatorFilterObject, self).__init__(base_uri)
        self._owners = []

        # pd('IndicatorFilterObject', header=True)
        # pd('indicator_type_enum', indicator_type_enum)

        self._properties = BulkIndicatorsProperties(base_uri=self.base_uri)
        self._resource_type = self._properties.resource_type

        # create default request object for filtered request with only owners
        self._request_object = RequestObject('indicators', 'default')
        self._request_object.set_http_method(self._properties.http_method)
        self._request_object.set_owner_allowed(self._properties.base_owner_allowed)
        self._request_object.set_request_uri(self._properties.base_path)
        self._request_object.set_resource_pagination(self._properties.resource_pagination)
        self._request_object.set_resource_type(self._properties.resource_type)

        #
        # add_obj filter methods
        #
        for method_name in self._properties.filters:
            # pd('method_name', method_name)
            method = getattr(FilterMethods, method_name)
            setattr(self, method_name, types.MethodType(method, self))
