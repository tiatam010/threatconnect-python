""" standard """
import types

""" custom """
from threatconnect import FilterMethods
from threatconnect.Properties.AttributesProperties import AttributesProperties
from threatconnect.Resource import Resource
from threatconnect.FilterObject import FilterObject

""" Note: PEP 8 intentionally ignored for variable/methods to match API standard. """


class Attributes(Resource):
    """ """
    def __init__(self, tc_obj):
        """ """
        super(Attributes, self).__init__(tc_obj)
        self._filter_class = AttributeFilterObject
        # self._object_class = AttributeObject

        # set properties for non filtered request
        properties = AttributesProperties(base_uri=self.base_uri)
        self._http_method = properties.http_method
        self._owner_allowed = properties.base_owner_allowed
        self._resource_pagination = properties.resource_pagination
        self._request_uri = properties.base_path
        self._resource_type = properties.resource_type


# class AttributeObject(ResourceObject):
#     """ """
#     def __init__(self, data_methods):
#         """ """
#         super(AttributeObject, self).__init__()
#
#         #
#         # build data to method mapping
#         #
#         self._data_methods = {}
#         for data_name, methods in data_methods.items():
#             # create variables for object
#             attribute = methods['var']
#             if attribute is not None:
#                 setattr(self, attribute, None)
#
#             # create add_obj methods for object
#             method_name = methods['set']
#             method = getattr(ResourceMethods, method_name)
#             setattr(self, method_name, types.MethodType(method, self))
#
#             # build api data name to method mapping
#             if method_name not in self._data_methods:
#                 self._data_methods[data_name] = getattr(self, method_name)
#
#             # create add_obj methods for object
#             method_name = methods['get']
#             if method_name is not None:
#                 method = getattr(ResourceMethods, method_name)
#                 setattr(self, method_name, types.MethodType(method, self))
#                 self.add_method({
#                     'name': attribute,
#                     'method_name': method_name})


class AttributeFilterObject(FilterObject):
    """ """
    def __init__(self, base_uri):
        """ """
        super(AttributeFilterObject, self).__init__(base_uri)
        self._owners = []

        # define properties for resource type
        self._properties = AttributesProperties(base_uri=self.base_uri)
        self._owner_allowed = self._properties.base_owner_allowed
        self._resource_pagination = self._properties.resource_pagination
        self._request_uri = self._properties.base_path
        self._resource_type = self._properties.resource_type

        #
        # add_obj filter methods
        #
        for method_name in self._properties.filters:
            method = getattr(FilterMethods, method_name)
            setattr(self, method_name, types.MethodType(method, self))
