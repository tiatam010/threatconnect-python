""" standard """
import types

""" custom """
from threatconnect import FilterMethods, ResourceMethods
from threatconnect.Config.IndicatorType import IndicatorType
from threatconnect.Config.ResourceProperties import ResourceProperties
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.FilterObject import FilterObject
from threatconnect.Properties.IndicatorsProperties import IndicatorsProperties
from threatconnect.Resource import Resource, ResourceObject

""" Note: PEP 8 intentionally ignored for variable/methods to match API standard. """


class Indicators(Resource):
    """ """
    def __init__(self, tc_obj):
        """ """
        super(Indicators, self).__init__(tc_obj)
        self._object_class = IndicatorObject
        self._filter_class = IndicatorFilterObject
        self._modified_since = None

        # set properties
        properties = IndicatorsProperties()
        self._http_method = properties.http_method
        self._owner_allowed = properties.base_owner_allowed
        self._resource_pagination = properties.resource_pagination
        self._request_uri = properties.base_path
        self._resource_type = properties.resource_type

    def get_indicators(self):
        """ """
        for obj in self._objects:
            yield obj.get_indicator()

    def get_modified_since(self):
        """ """
        return self._modified_since

    def set_modified_since(self, data):
        """ """
        self._modified_since = data


class IndicatorObject(ResourceObject):
    """ """
    def __init__(self, data_methods):
        """ """
        super(IndicatorObject, self).__init__()
        # pd('resource_type_enum', resource_type_enum)

        #
        # build data to method mapping
        #
        self._data_methods = {}
        for data_name, methods in data_methods.items():
            # create variables for object
            attribute = methods['var']
            if attribute is not None:
                setattr(self, attribute, None)

            # create add methods for object
            method_name = methods['set']
            method = getattr(ResourceMethods, method_name)
            setattr(self, method_name, types.MethodType(method, self))

            # build api data name to method mapping
            if method_name not in self._data_methods:
                self._data_methods[data_name] = getattr(self, method_name)

            # create add methods for object
            method_name = methods['get']
            if method_name is not None:
                method = getattr(ResourceMethods, method_name)
                setattr(self, method_name, types.MethodType(method, self))
                self.add_method({
                    'name': attribute,
                    'method_name': method_name})


class IndicatorFilterObject(FilterObject):
    """ """
    def __init__(self, indicator_type_enum=None):
        """ """
        super(IndicatorFilterObject, self).__init__()
        self._owners = []

        # pd('IndicatorFilterObject', header=True)
        # pd('indicator_type_enum', indicator_type_enum)

        # get resource type from indicator type
        if isinstance(indicator_type_enum, IndicatorType):
            # get resource type from indicator type number
            resource_type = ResourceType(indicator_type_enum.value)

            # get resource properties from resource type name
            self._properties = ResourceProperties[resource_type.name].value()
        else:
            self._properties = ResourceProperties['INDICATORS'].value()

        # add properties for filter objects with no request object
        # happens when a indicator type is specified, but no other
        # filters are provided
        self._owner_allowed = self._properties.base_owner_allowed
        self._request_uri = self._properties.base_path
        self._resource_pagination = self._properties.resource_pagination
        self._resource_type = self._properties.resource_type

        # pd('owner_allowed', self._owner_allowed)
        # pd('resource_pagination', self._resource_pagination)
        # pd('resource_type', self._resource_type)

        #
        # add filter methods
        #
        for method_name in self._properties.filters:
            # pd('method_name', method_name)
            method = getattr(FilterMethods, method_name)
            setattr(self, method_name, types.MethodType(method, self))
