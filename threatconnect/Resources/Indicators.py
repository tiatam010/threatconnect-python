""" standard """
import types

""" custom """
from threatconnect import FilterMethods
from threatconnect.Config.IndicatorType import IndicatorType
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceProperties import ResourceProperties
from threatconnect.Config.ResourceRegexes import indicators_regex
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.FilterObject import FilterObject
from threatconnect.Properties.IndicatorsProperties import IndicatorsProperties
from threatconnect.Resource import Resource
from threatconnect.Validate import validate_indicator, _get_resource_type

""" Note: PEP 8 intentionally ignored for variable/methods to match API standard. """


class Indicators(Resource):
    """ """
    def __init__(self, tc_obj):
        """ """
        super(Indicators, self).__init__(tc_obj)
        # self._object_class = IndicatorObject
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

    def add_indicator(self, indicator):
        """ """
        print('indicator: %s' % indicator)
        # indicator set method
        indicator_set_methods = {
            'ADDRESS': 'set_ip',
            'EMAIL_ADDRESS': 'set_address',
            'FILE': 'set_hash',
            'HOST': 'set_hostname',
            'URL': 'set_text'}

        # validate indicator
        if validate_indicator(indicator):
            # get indicator type
            resource_type = _get_resource_type(indicator)

            # set properties
            resource_type = ResourceType(resource_type.value - 5)
            properties = ResourceProperties[resource_type.name].value(PropertiesAction.POST)
            self._http_method = properties.http_method
            self._owner_allowed = False
            self._resource_pagination = False
            self._request_uri = properties.post_path
            self._resource_type = properties.resource_type

            # resource object
            self._resource_object = properties.resource_object

            # set indicator
            set_method = getattr(
                self._resource_object, indicator_set_methods[resource_type.name])
            set_method(indicator)

            return self._resource_object
        else:
            print('(%s) is an invalid indicator.' % indicator)

        return None

    def get_json(self):
        """ """
        return self._resource_object.get_json()

    def send(self):
        """ """
        if self._resource_object.validate():
            data_set = self._tc._api_build_request(self, body=self.get_json())
            for obj in data_set:
                self.add(obj)
        else:
            print('validation failed')
            print(self._resource_object)


# class IndicatorPost(object):
#     """ """
#     def __init__(self, tc_obj, indicator):
#         """ """
#         # super(IndicatorPost, self).__init__()
#         self._tc = tc_obj
#         self._indicator = indicator
#
#         # indicator set method
#         indicator_set_methods = {
#             'ADDRESS': 'set_ip',
#             'EMAIL_ADDRESS': 'set_address',
#             'FILE': 'set_hash',
#             'HOST': 'set_hostname',
#             'URL': 'set_text'}
#
#         # validate indicator
#         if validate_indicator(indicator):
#             # get indicator type
#             resource_type = _get_resource_type(indicator)
#
#             # set properties
#             self._resource_type = ResourceType(resource_type.value - 5)
#             self._properties = ResourceProperties[self._resource_type.name].value(PropertiesAction.POST)
#
#             # resource object
#             self._resource_object = self._properties.resource_object
#
#             # set indicator
#             set_method = getattr(
#                 self._resource_object, indicator_set_methods[self._resource_type.name])
#             set_method(self._indicator)
#             # self._resource_object.set_ip(self._indicator)
#             # self._resource_object.set_address(self._indicator)
#
#     def build_indicator(self):
#         """ """
#         return self._resource_object
#
#     def get_json(self):
#         """ """
#         return self._resource_object.get_json()
#
#     def post(self):
#         """ """
#         if self._resource_object.validate():
#             print('validation passed')
#             print(self._resource_object)
#             payload = {'owner': 'Test & Org'}
#             response = self._tc._api_request(
#                 self._properties.write_path, payload, 'POST', body=self._resource_object.get_json())
#             from pprint import pprint
#             pprint(response)
#         else:
#             print('validation failed')
#             print(self._resource_object)



# class IndicatorObject(ResourceObject):
#     """ """
#     def __init__(self, data_methods):
#         """ """
#         super(IndicatorObject, self).__init__()
#         # pd('resource_type_enum', resource_type_enum)
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
#             # create add methods for object
#             method_name = methods['set']
#             method = getattr(ResourceMethods, method_name)
#             setattr(self, method_name, types.MethodType(method, self))
#
#             # build api data name to method mapping
#             if method_name not in self._data_methods:
#                 self._data_methods[data_name] = getattr(self, method_name)
#
#             # create add methods for object
#             method_name = methods['get']
#             if method_name is not None:
#                 method = getattr(ResourceMethods, method_name)
#                 setattr(self, method_name, types.MethodType(method, self))
#                 self.add_method({
#                     'name': attribute,
#                     'method_name': method_name})


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
