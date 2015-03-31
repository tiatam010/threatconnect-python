""" standard """
import types

""" custom """
from threatconnect import FilterMethods, ResourceMethods
from threatconnect.Properties.OwnersProperties import OwnersProperties
from threatconnect.FilterObject import FilterObject
from threatconnect.Resource import (Resource, ResourceObject)

""" Note: PEP 8 intentionally ignored for variable/methods to match API standard. """


class Owners(Resource):
    """ """
    def __init__(self, tc_obj):
        """ """
        super(Owners, self).__init__(tc_obj)
        self._object_class = OwnerObject
        self._filter_class = OwnerFilterObject

        # set properties
        properties = OwnersProperties()
        self._http_method = properties.http_method
        self._owner_allowed = properties.indicator_owner_allowed
        self._resource_pagination = properties.resource_pagination
        self._request_uri = properties.base_path
        self._resource_type = properties.resource_type

    def get_owner_by_id(self, data):
        for obj in self._objects:
            if obj.get_id() == data:
                return obj
        return None

    def get_owner_by_name(self, data):
        for obj in self._objects:
            if obj.get_name() == data:
                return obj
        return None

    def get_owner_names(self):
        owner_names = []
        for obj in self._objects:
            owner_names.append(obj.get_name())
        return owner_names


class OwnerObject(ResourceObject):
    """ """
    def __init__(self, data_methods):
        """ """
        super(OwnerObject, self).__init__()

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


class OwnerFilterObject(FilterObject):
    """ """

    def __init__(self):
        """ """
        super(OwnerFilterObject, self).__init__()
        self._property_class = OwnersProperties
        self._properties_class = OwnersProperties

        # define properties for resource type
        self._properties = self._properties_class()
        self._owner_allowed = self._properties.base_owner_allowed
        self._resource_pagination = self._properties.resource_pagination
        self._request_uri = self._properties.base_path
        self._resource_type = self._properties.resource_type

        #
        # add filter methods
        #
        for method_name in self._properties.filters:
            method = getattr(FilterMethods, method_name)
            setattr(self, method_name, types.MethodType(method, self))
