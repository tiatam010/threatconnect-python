""" standard """
import sys

""" custom """
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.PropertiesEnums import ApiStatus
from threatconnect.Config.ResourceProperties import ResourceProperties
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.DataFormatter import (format_header, format_item)


class Resource(object):
    """ """
    def __init__(self, tc_obj):
        """ """
        self._tc = tc_obj

        self._objects = []
        self._resource_objects = []

        # indexes
        self._object_id_idx = {}
        self._object_name_idx = {}
        self._resource_id_idx = {}

        # defaults
        self._api_response = []
        self._current_filter = None
        self._error = False
        self._error_messages = []
        self._filter_class = None
        self._filter_objects = []
        self._http_method = None
        self._max_results = None
        self._method = None
        self._object_class = None
        self._owners = []
        self._owner_allowed = False
        self._request_object = None
        self._request_uri = None
        self._resource_object = None
        self._resource_pagination = False
        self._resource_type = None
        self._result_count = 0
        self._status = ApiStatus.SUCCESS
        self._status_code = []
        self._uris = []

    def add(self, data_obj):
        """ """
        if data_obj.get_id() is None:
            # prefer to use id as index
            index = data_obj.get_name()
        else:
            # use name if id is not available
            index = data_obj.get_id()

        if index not in self._object_id_idx:
            self._objects.append(data_obj)

            # build indexes
            if data_obj.get_id() is not None:
                self._object_id_idx.setdefault(data_obj.get_id(), data_obj)

            if hasattr(data_obj, 'get_name'):
                self._object_name_idx.setdefault(data_obj.get_name(), []).append(data_obj)

    def add_api_response(self, data):
        """ """
        self._api_response.append(data)

    def add_error_message(self, data):
        """ """
        self._error_messages.append(data)

    def add_filter(self, resource_type=None):
        if resource_type is not None:
            filter_obj = self._filter_class(resource_type)
        else:
            filter_obj = self._filter_class()

        # append filter object
        self._filter_objects.append(filter_obj)
        return filter_obj

    def add_owners(self, data):
        """ """
        if isinstance(data, list):
            self._owners.extend(data)
        else:
            self._owners.append(data)

    def add_resource(self, resource):
        """ """
        # set properties
        if self._resource_type.value % 10:
            self._resource_type = ResourceType(self._resource_type.value - 5)
        properties = ResourceProperties[self._resource_type.name].value(PropertiesAction.POST)
        self._http_method = properties.http_method
        self._owner_allowed = False
        self._resource_pagination = False
        self._request_uri = properties.post_path

        # resource object
        self._resource_object = properties.resource_object

        # set indicator
        self._resource_object.set_name(resource)

        return self._resource_object

    def add_resource_obj(self, data_obj):
        """ """
        if data_obj.get_id() is None:
            # prefer to use id as index
            index = data_obj.get_name()
        else:
            # use name if id is not available
            index = data_obj.get_id()

        if index not in self._resource_id_idx:
            self._resource_objects.append(data_obj)
            # build index
            self._resource_id_idx.setdefault(index, data_obj)
        else:
            # print('skip')
            pass

    def add_result_count(self, data_int):
        """ """
        self._result_count += data_int

    def add_status(self, data_enum):
        """ """
        self._status = ApiStatus(self._status.value & data_enum.value)

    def add_status_code(self, data_int):
        """ """
        self._status_code.append(data_int)

    def add_uris(self, data):
        """ """
        if isinstance(data, list):
            self._uris.extend(data)
        else:
            self._uris.append(data)

    def delete(self, resource_id):
        """ """
        # set properties
        if self._resource_type.value % 10:
            self._resource_type = ResourceType(self._resource_type.value - 5)
        properties = ResourceProperties[self._resource_type.name].value(PropertiesAction.DELETE)
        self._http_method = properties.http_method
        self._owner_allowed = False
        self._resource_pagination = False
        uri_attribute = properties.resource_uri_attribute
        self._request_uri = properties.delete_path % (uri_attribute, resource_id)

        data_set = self._tc._api_build_request(self)
        for obj in data_set:
            self.add(obj)

    def get_api_response(self):
        """ """
        return self._api_response

    def get_current_filter(self):
        """ """
        return self._current_filter

    def get_http_method(self):
        """ """
        return self._http_method

    def get_json(self):
        """ """
        return self._resource_object.get_json()

    def get_max_results(self):
        """ """
        return self._max_results

    def get_object_class(self):
        """ """
        return self._object_class

    def get_owner_allowed(self):
        """ """
        return self._owner_allowed

    def get_owners(self):
        """ """
        return self._owners

    def get_resource_pagination(self):
        """ """
        return self._resource_pagination

    def get_resource_by_id(self, data):
        """ """
        if data in self._resource_id_idx:
            return self._resource_id_idx[data]
        else:
            print('(%s) was not found in index.' % data)
            sys.exit(1)

    def get_resource_by_name(self, data):
        """ """
        if data in self._resource_id_idx:
            return self._resource_id_idx[data]
        else:
            print('(%s) was not found in index.' % data)
            sys.exit(1)

    def get_request_uri(self):
        """ """
        return self._request_uri

    def get_result_count(self):
        """ """
        return self._result_count

    def get_status(self):
        """ """
        return self._status

    def get_status_code(self):
        """ """
        return self._status_code

    def get_uris(self):
        """ """
        return self._uris

    @property
    def request_object(self):
        """ """
        return self._request_object

    @property
    def resource_type(self):
        """ """
        return self._resource_type

    def retrieve(self):
        """ """
        good_filters = []
        for filter_obj in self._filter_objects:
            if filter_obj.error:
                self._error_messages = True
                for filter_error in filter_obj.get_errors():
                    self.add_error_message(filter_error)
            else:
                good_filters.append(filter_obj)

        # retrieve resources for good filters
        if not self._error_messages:
            self._tc.get_filtered_resource(self, good_filters)

    def send(self):
        """ """
        if self._resource_object.validate():
            data_set = self._tc._api_build_request(self, body=self.get_json())
            for obj in data_set:
                self.add(obj)
        else:
            print('Validation of email failed.')
            print(self._resource_object)

    def set_current_filter(self, data):
        """ """
        self._current_filter = data

    def set_http_method(self, data):
        """ """
        self._http_method = data

    def set_max_results(self, data_int):
        """ """
        self._max_results = int(data_int)

    def set_owner_allowed(self, data):
        """ """
        self._owner_allowed = data

    def set_resource_pagination(self, data):
        """ """
        self._resource_pagination = data

    def set_request_object(self, data_obj):
        """ """
        self._request_object = data_obj

    def set_request_uri(self, data):
        """ """
        self._request_uri = data

    def set_resource_type(self, data_enum):
        """ """
        self._resource_type = data_enum

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

    def __iter__(self):
        """ """
        for obj in self._objects:
            yield obj

    def __len__(self):
        """ """
        return len(self._objects)

    def __str__(self):
        """ """
        obj_str = format_header('Resource Object')
        printable_items = dict(self.__dict__)
        for key, val in sorted(printable_items.items()):
            obj_str += format_item(key, val)

        return obj_str


class ResourceObject(object):
    """ """
    def __init__(self):
        """ """
        self._id = None
        self._data_methods = None
        self._methods = []
        self._matched_filters = []
        self._name = None
        self._object_type = None
        self._url = None

    # def add_id(self, data):
    #     """ """
    #     self._id = data

    def add_matched_filter(self, data):
        """ """
        self._matched_filters.append(data)

    def add_method(self, data):
        """ """
        self._methods.append(data)

    # def add_name(self, data):
    #     """ """
    #     self._name = data

    def add_request_url(self, data):
        """ """
        self._url = data

    # def get_id(self):
    #     """ """
    #     return self._id

    def get_data_methods(self):
        """ """
        return self._data_methods

    def get_matched_filters(self):
        """ """
        return self._matched_filters

    def get_methods(self):
        """ """
        return self._methods

    # def get_name(self):
    #     """ """
    #     return self._name

    def get_request_url(self):
        """ """
        return self._url

    def __str__(self):
        """ """
        if self.get_name() is not None:
            obj_str = format_header('%s' % self.get_name())
        else:
            obj_str = format_header('%s' % 'Resource')
        printable_items = dict(self.__dict__)
        printable_items.pop('_data_methods')
        printable_items.pop('_object_type')
        for key, val in sorted(printable_items.items()):
            obj_str += format_item(key, val)

        return obj_str


# class ResourceObjectExtended(ResourceObject):
#     """ """
#
#     def __init__(self):
#         """ """
#         super(ResourceObjectExtended, self).__init__()
#         self._dateAdded = None
#         self._ownerName = None
#         self._webLink = None
#
#     def add_dateAdded(self, data):
#         """ """
#         self._dateAdded = data
#
#     def add_ownerName(self, data):
#         """ """
#         self._ownerName = data
#
#     def add_webLink(self, data):
#         """ """
#         self._webLink = data
#
#     def get_ownerName(self):
#         """ """
#         return self._ownerName
#
#     def get_dateAdded(self):
#         """ """
#         return self._dateAdded
#
#     def get_webLink(self):
#         """ """
#         return self._webLink


# class IndicatorResourceObject(ResourceObject):
#     """ """
#
#     def __init__(self):
#         """ """
#         super(IndicatorResourceObject, self).__init__()
#         self._confidence = None
#         self._dateAdded = None
#         self._description = None
#         self._lastModified = None
#         self._indicator = None
#         self._owner = None
#         self._ownerName = None
#         # self._summary = None
#         self._threatAssessConfidence = None
#         self._threatAssessRating = None
#         self._type = None
#         self._webLink = None

