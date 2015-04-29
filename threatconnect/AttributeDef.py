""" standard """

""" custom """
from threatconnect.DataFormatter import format_item, format_header
from threatconnect.ResourceMethods import *


class AttributeDef(object):
    """ """

    def __init__(self, name):
        """ """
        self._attr_name = name

        self._attr_api_names = []
        self._attr_method_set = None
        self._attr_method_get = None
        self._attr_required = False
        self._attr_type = types.NoneType
        self._attr_writable = False
        self._extra_attributes = []
        self._extra_methods = []

    def add_api_name(self, data):
        """ """
        self._attr_api_names.append(data)

    def add_extra_attribute(self, data):
        """ """
        self._extra_attributes.append(data)

    def add_extra_method(self, data):
        """ """
        self._extra_methods.append(data)

    def set_method_get(self, data):
        """ """
        self._attr_method_get = data

    def set_method_set(self, data):
        """ """
        self._attr_method_set = data

    def set_type(self, data):
        """ """
        self._attr_type = data

    def set_required(self, data_bool):
        """ """
        self._attr_required = data_bool

    def set_writable(self, data_bool):
        """ """
        self._attr_writable = data_bool

    @property
    def api_names(self):
        """ """
        return self._attr_api_names

    @property
    def extra_attributes(self):
        """ """
        return self._extra_attributes

    @property
    def extra_methods(self):
        """ """
        return self._extra_methods

    @property
    def name(self):
        """ """
        return self._attr_name

    @property
    def method_get(self):
        """ """
        return self._attr_method_get

    @property
    def method_set(self):
        """ """
        return self._attr_method_set

    @property
    def required(self):
        """ """
        return self._attr_required

    @property
    def type(self):
        """ """
        if self._attr_type is types.NoneType:
            return None
        elif self._attr_type is types.IntType:
            return 0
        elif self._attr_type is types.ListType:
            return []
        elif self._attr_type is types.BooleanType:
            return False

    @property
    def writable(self):
        """ """
        return self._attr_writable

    def __str__(self):
        """ """
        obj_str = ''
        for k, v in self.__dict__.viewitems():
            obj_str += format_item(k, v)

        return obj_str
