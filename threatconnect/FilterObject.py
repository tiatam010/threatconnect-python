""" standard """

""" custom """
from threatconnect.Config.PropertiesEnums import FilterSetOperator
from threatconnect.DataFormatter import (format_header, format_item)
from threatconnect.ErrorCodes import ErrorCodes

""" Note: PEP 8 intentionally ignored for variable/methods to match API standard. """


class FilterObject(object):
    """ """
    def __init__(self, base_uri):
        """ """
        self.base_uri = base_uri

        self._error = False
        self._errors = []
        self._filter_operator = FilterSetOperator.AND
        self._filter_object_type = None
        self._post_filters = []
        self._resource_type = None
        self._request_object = None
        self._request_objects = []

    @property
    def error(self):
        """ """
        return self._error

    def _add_error(self, data):
        """ """
        self._errors.append(data)

    def _add_request_objects(self, data_obj):
        """ """
        self._request_objects.append(data_obj)

    def add_filter_operator(self, data_enum):
        """ """
        if not isinstance(data_enum, FilterSetOperator):
            self._add_error(ErrorCodes.e1000.value % data_enum)
        else:
            self._filter_operator = data_enum

    def add_post_filter(self, data_obj):
        """ """
        self._post_filters.append(data_obj)

    # def get_base_uri(self):
    #     """ """
    #     return self._base_uri

    def get_errors(self):
        """ """
        return self._errors

    def get_filter_operator(self):
        """ """
        return self._filter_operator

    def get_post_filters(self):
        """ """
        for obj in self._post_filters:
            yield obj

    def get_post_filters_len(self):
        """ """
        return len(self._post_filters)

    @property
    def request_object(self):
        """ """
        return self._request_object

    @property
    def resource_type(self):
        """ """
        return self._resource_type

    def __iter__(self):
        """ """
        for obj in self._request_objects:
            yield obj

    def __len__(self):
        """ """
        return len(self._request_objects)

    def __str__(self):
        """ """
        obj_str = format_header('%s Filter Object' % self._resource_type.name)
        printable_items = dict(self.__dict__)
        for key, val in sorted(printable_items.items()):
            obj_str += format_item(key, val)

        return obj_str

