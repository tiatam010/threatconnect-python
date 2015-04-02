""" standard """
import sys
import types

""" custom """
from threatconnect import FilterMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceProperties import ResourceProperties
from threatconnect.Properties.EmailsProperties import EmailsProperties
from threatconnect.Resource import Resource, ResourceObject
from threatconnect.FilterObject import FilterObject

""" Note: PEP 8 intentionally ignored for variable/methods to match API standard. """


class Emails(Resource):
    """ """

    def __init__(self, tc_obj):
        """ """
        super(Emails, self).__init__(tc_obj)
        self._filter_class = EmailFilterObject

        # set properties for non filtered request
        properties = EmailsProperties()
        self._http_method = properties.http_method
        self._owner_allowed = properties.base_owner_allowed
        self._resource_pagination = properties.resource_pagination
        self._request_uri = properties.base_path
        self._resource_type = properties.resource_type

    # def add_resource(self, resource):
    #     """ """
    #     # set properties
    #     if self._resource_type.value % 10:
    #         self._resource_type = ResourceType(self._resource_type.value - 5)
    #     properties = ResourceProperties[self._resource_type.name].value(PropertiesAction.POST)
    #     self._http_method = properties.http_method
    #     self._owner_allowed = False
    #     self._resource_pagination = False
    #     self._request_uri = properties.post_path
    #
    #     # resource object
    #     self._resource_object = properties.resource_object
    #
    #     # set indicator
    #     self._resource_object.set_name(resource)
    #
    #     return self._resource_object

    # def delete(self, resource_id):
    #     """ """
    #     # set properties
    #     if self._resource_type.value % 10:
    #         self._resource_type = ResourceType(self._resource_type.value - 5)
    #     properties = ResourceProperties[self._resource_type.name].value(PropertiesAction.DELETE)
    #     self._http_method = properties.http_method
    #     self._owner_allowed = False
    #     self._resource_pagination = False
    #     uri_attribute = properties.resource_uri_attribute
    #     self._request_uri = properties.delete_path % (uri_attribute, resource_id)
    #
    #     data_set = self._tc._api_build_request(self)
    #     for obj in data_set:
    #         self.add(obj)

    def update(self, resource_id):
        """ """
        # set properties
        if self._resource_type.value % 10:
            self._resource_type = ResourceType(self._resource_type.value - 5)
        properties = ResourceProperties[self._resource_type.name].value(PropertiesAction.PUT)
        self._http_method = properties.http_method
        self._owner_allowed = False
        self._resource_pagination = False
        uri_attribute = properties.resource_uri_attribute
        self._request_uri = properties.put_path % (uri_attribute, resource_id)

        # resource object
        self._resource_object = properties.resource_object

        return self._resource_object

    # def get_json(self):
    #     """ """
    #     return self._resource_object.get_json()
    #
    # def send(self):
    #     """ """
    #     if self._resource_object.validate():
    #         data_set = self._tc._api_build_request(self, body=self.get_json())
    #         for obj in data_set:
    #             self.add(obj)
    #     else:
    #         print('Validation of email failed.')
    #         print(self._resource_object)


# class EmailObject(ResourceObject):
# """ """
#     def __init__(self, data_methods):
#         """ """
#         super(EmailObject, self).__init__()
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


class EmailFilterObject(FilterObject):
    """ """

    def __init__(self):
        """ """
        super(EmailFilterObject, self).__init__()
        self._owners = []

        # define properties for resource type
        self._properties = EmailsProperties()
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
