""" standard """
import sys
import types

""" custom """
from threatconnect import FilterMethods, ResourceMethods
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Properties.DnsResolutionProperties import DnsResolutionProperties
from threatconnect.Resource import Resource
from threatconnect.FilterObject import FilterObject

""" Note: PEP 8 intentionally ignored for variable/methods to match API standard. """


class DnsResolutions(Resource):
    """ """
    def __init__(self, tc_obj):
        """ """
        super(DnsResolutions, self).__init__(tc_obj)
        self._object_class = DnsResolutionObject
        self._filter_class = DnsResolutionFilterObject

        # set properties for non filtered request
        properties = DnsResolutionProperties()
        self._http_method = properties.http_method
        self._owner_allowed = properties.base_owner_allowed
        self._resource_pagination = properties.resource_pagination
        self._request_uri = properties.base_path
        self._resource_type = properties.resource_type


class DnsResolutionObject(object):
    """ """
    def __init__(self, resource_type_enum=None):
        """ """
        super(DnsResolutionObject, self).__init__()

        self._resource_type = resource_type_enum
        self._property_class = DnsResolutionProperties
        self._properties_class = DnsResolutionProperties

        # define properties for resource type
        if resource_type_enum == ResourceType.ADVERSARY:
            properties = self._property_class()
        elif resource_type_enum == ResourceType.ADVERSARIES:
            properties = self._properties_class()
        else:
            sys.exit(1)

        #
        # build data to method mapping
        #
        self._data_methods = {}
        for data_name, methods in properties.data_methods.viewitems():
            # create variables for object
            attribute = methods['var']
            if attribute is not None:
                setattr(self, attribute, None)

            # create add_obj methods for object
            method_name = methods['set']
            method = getattr(ResourceMethods, method_name)
            setattr(self, method_name, types.MethodType(method, self))

            # build api data name to method mapping
            if method_name not in self._data_methods:
                self._data_methods[data_name] = getattr(self, method_name)

            # create add_obj methods for object
            method_name = methods['get']
            if method_name is not None:
                method = getattr(ResourceMethods, method_name)
                setattr(self, method_name, types.MethodType(method, self))
                self.add_method({
                    'name': attribute,
                    'method_name': method_name})


class DnsResolutionFilterObject(FilterObject):
    """ """
    def __init__(self):
        """ """
        super(DnsResolutionFilterObject, self).__init__()
        self._owners = []

        # define properties for resource type
        self._property_class = DnsResolutionProperties
        self._properties_class = DnsResolutionProperties

        # define properties for resource type
        self._properties = self._properties_class()
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
