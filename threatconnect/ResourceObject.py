""" standard """
import json

""" custom """
import threatconnect.ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.DataFormatter import format_item, format_header
from threatconnect.ResourceMethods import *


# def resource_class(dynamic_attributes):
def resource_class(dynamic_attribute_objs, action=PropertiesAction.READ):
    """
    This method will dynamically generate a ResourceObject class given
    an AttributeDef object. This method uses the passed object
    to build slots in the Class. Using slots *should* increase performance
    due to the large number of these objects being generated.

    Named Tuple Format:
    * attr_required: if the attribute is required during write operations.
    * attr:          the attribute name
    * attr_type:     the attribute type (e.g. NoneType, IntType, BooleanType)
    * methods:       a tuple of methods for managing this attribute
    """

    attributes = (
        '_a_names',
        '_data_methods',
        '_error_msgs',
        '_json_data',
        '_methods',
        '_raw_response',
        '_request_url',
        '_required_attrs',
        '_validated',
        '_writable_attrs')

    for data_obj in dynamic_attribute_objs:
        attributes += tuple(data_obj.name)  # add attr to tuple of attributes
        attributes += tuple(data_obj.method_get)
        attributes += tuple(data_obj.method_set)

    class ResourceObject():
        __slots__ = attributes

        def __init__(self):
            self._a_names = []
            self._data_methods = {}
            self._error_msgs = []
            self._json_data = {}
            self._methods = []
            self._request_url = None
            self._required_attrs = []
            self._validated = False
            self._writable_attrs = {}

            # add name to 'a list' for __str__ method
            self.a_names('_error_msgs')
            self.a_names('_methods')
            self.a_names('_request_url')
            self.a_names('_required_attrs')
            self.a_names('_validated')
            self.a_names('_writable_attrs')

            for a_obj in dynamic_attribute_objs:
                # create the attribute with the default value
                setattr(self, a_obj.name, a_obj.type)

                # add required attribute to required list
                if a_obj.required and action == PropertiesAction.WRITE:
                    self.add_required_attr(a_obj.name)

                # add writable to writable list
                if a_obj.writable and action == PropertiesAction.WRITE:
                    self.add_writable_attr(a_obj.api_names[0], a_obj.name)

                # add get method
                get_method = getattr(threatconnect.ResourceMethods, a_obj.method_get)
                setattr(self, a_obj.method_get, types.MethodType(get_method, self))

                # only add get methods
                if action == PropertiesAction.READ:
                    self.add_method(a_obj.method_get)

                # add set method
                set_method = getattr(threatconnect.ResourceMethods, a_obj.method_set)
                setattr(self, a_obj.method_set, types.MethodType(set_method, self))

                # only add write methods
                if action == PropertiesAction.WRITE and a_obj.writable:
                    self.add_method(a_obj.method_set)

                # if a_obj.api_name is not None:
                for api_name in a_obj.api_names:
                    # self._data_methods[a_obj.api_name] = a_obj.method_set
                    # self._data_methods[a_obj.api_name] = getattr(self, a_obj.method_set)
                    self._data_methods[api_name] = getattr(self, a_obj.method_set)

                # add attribute name to a_names list for __str__ method
                self.a_names(a_obj.name)

        def a_names(self, data):
            """ """
            self._a_names.append(data)

        def add_error_msg(self, data):
            """ """
            self._error_msgs.append(data)

        def add_method(self, data):
            """ """
            self._methods.append(data)

        def add_required_attr(self, data):
            """ """
            self._required_attrs.append(data)

        def add_writable_attr(self, data_key, data_val):
            """ """
            self._writable_attrs[data_key] = data_val

        def get_data_methods(self):
            """ """
            return self._data_methods

        def get_error(self):
            """ """
            if len(self._error_msgs) > 0:
                return True
            else:
                return False

        def get_error_msgs(self):
            """ """
            return self._error_msgs

        def get_json(self):
            """ """
            json_dict = {}
            for key, val in self._writable_attrs.items():
                data_val = getattr(self, val)
                print(key)
                print(data_val)
                if data_val is not None:
                    json_dict[key] = data_val
            return json.dumps(json_dict)

        def get_methods(self):
            """ """
            return self._methods

        def get_request_url(self):
            """ """
            return self._request_url

        def get_required_attrs(self):
            """ """
            return self._required_attrs

        def get_writable_attrs(self):
            """ """
            return self._writable_attrs

        def set_request_url(self, data):
            """ """
            self._request_url = data

        def validate(self):
            """ """
            if len(self._error_msgs) > 0:
                return False

            for required in self._required_attrs:
                val = getattr(self, required)

                if val is None:
                    # fail if any required attribute is None
                    return False
                elif isinstance(val, list):
                    if not val:
                        # fail if any required attribute list is empty
                        return False

            self._validated = True
            return self._validated

        def __str__(self):
            """allow object to be displayed with print"""
            printable_items = dict(self.__dict__)
            if hasattr(self, 'get_indicator'):
                obj_str = format_header(self.get_indicator())
                printable_items.pop('_indicator')
            elif hasattr(self, 'get_name'):
                obj_str = format_header(self.get_name())
                printable_items.pop('_name')
            elif hasattr(self, 'get_id'):
                obj_str = format_header(self.get_id())
                printable_items.pop('_id')
            else:
                obj_str = format_header('ResourceObject')

            for key, val in sorted(printable_items.items()):
                if key in self._a_names:
                    obj_str += format_item(key, val)
            return obj_str

    return ResourceObject


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

    def add_api_name(self, data):
        """ """
        self._attr_api_names.append(data)

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
        for k, v in self.__dict__.items():
            obj_str += format_item(k, v)

        return obj_str
