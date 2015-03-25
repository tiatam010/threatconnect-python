""" standard """

""" custom """
# from threatconnect.Properties.Properties import Properties
# from threatconnect.Properties.ApiData import IndicatorType
from threatconnect.Config.PropertiesEnums import FilterSetOperator
from threatconnect.DataFormatter import (format_header, format_item)
from threatconnect.ErrorCodes import ErrorCodes
# from threatconnect.RequestObject import RequestObject
# from threatconnect.Validate import validate_indicator

""" Note: PEP 8 intentionally ignored for variable/methods to match API standard. """


# def get_indicator_type(indicator):
#     """ """
#     for member in IndicatorRegEx:
#         for regex in member.value:
#             if regex.match(indicator):
#                 return IndicatorType[member.name]
#     return None


# def validate_int(data):
#     """ """
#     if isinstance(data, list):
#         for d in data:
#             if not isinstance(d, int):
#                 return False
#     else:
#         if not isinstance(data, int):
#             return False
#     return True


class FilterObject(object):
    """ """
    def __init__(self):
        """ """
        self._base_uri = None
        self._error = False
        self._errors = []
        self._filter_operator = FilterSetOperator.AND
        self._filter_object_type = None
        self._resource_type = None
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

    def get_base_uri(self):
        """ """
        return self._base_uri

    def get_errors(self):
        """ """
        return self._errors

    def get_filter_operator(self):
        """ """
        return self._filter_operator

    # def set_error(self, data):
    #     """ """
    #     self._error = data

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
        # printable_items.pop('_filter_object_type')
        # printable_items.pop('_request_objects')
        for key, val in sorted(printable_items.items()):
            obj_str += format_item(key, val)

        return obj_str


# class ResourceGroupFilterObject(FilterObject):
#     """ """
#     def __init__(self):
#         """ """
#         super(ResourceGroupFilterObject, self).__init__()
#         self._adversary_ids = []
#         self._email_ids = []
#         self._ids = []
#         self._incident_ids = []
#         self._indicators = []
#         self._owners = []
#         self._property_class = Properties
#         self._properties_class = Properties
#         self._security_labels = []
#         self._signature_ids = []
#         self._tags = []
#         self._threat_ids = []
#         self._victim_ids = []
#
#         self._request_objects = []
#
#     def add_adversary_id(self, data):
#         """ """
#         properties = self._properties_class()
#         # validation of data input
#         if not validate_int(data):
#             self._add_error(ErrorCodes.e4000.value % data)
#         else:
#             filter_type = 'adversary_id'
#             ro = RequestObject(filter_type, data)
#             ro.set_owner_allowed(properties.adversary_owner_allowed)
#             ro.set_resource_pagination(properties.resource_pagination)
#             ro.set_request_uri(properties.adversary_path, [data])
#             ro.set_resource_key(properties.resource_key)
#             self._add_request_objects(ro)
#
#     def add_email_id(self, data):
#         """ """
#         properties = self._properties_class()
#         # validation of data input
#         if not validate_int(data):
#             self._add_error(ErrorCodes.e4010.value % data)
#         else:
#             filter_type = 'email_id'
#             ro = RequestObject(filter_type, data)
#             ro.set_owner_allowed(properties.email_owner_allowed)
#             ro.set_resource_pagination(properties.resource_pagination)
#             ro.set_request_uri(properties.email_path, [data])
#             ro.set_resource_key(properties.resource_key)
#             self._add_request_objects(ro)
#
#     def add_id(self, data):
#         """ """
#         properties = self._property_class()
#         # validation of data input
#         if not validate_int(data):
#             self._add_error(ErrorCodes.e4020.value % data)
#         else:
#             filter_type = 'id'
#             ro = RequestObject(filter_type, data)
#             ro.set_owner_allowed(properties.id_owner_allowed)
#             ro.set_resource_pagination(properties.resource_pagination)
#             ro.set_request_uri(properties.id_path, [data])
#             ro.set_resource_key(properties.resource_key)
#             self._add_request_objects(ro)
#
#     def add_incident_id(self, data):
#         """ """
#         properties = self._properties_class()
#         # validation of data input
#         if not validate_int(data):
#             self._add_error(ErrorCodes.e4030.value % data)
#         else:
#             filter_type = 'incident_id'
#             ro = RequestObject(filter_type, data)
#             ro.set_owner_allowed(properties.incident_owner_allowed)
#             ro.set_resource_pagination(properties.resource_pagination)
#             ro.set_request_uri(properties.incident_path, [data])
#             ro.set_resource_key(properties.resource_key)
#             self._add_request_objects(ro)
#
#     def add_indicator(self, data, data_type_enum=None):
#         """ """
#         properties = self._properties_class()
#         # validation of data input
#         if data_type_enum is None:
#             data_type_enum = get_indicator_type(data)
#
#         # validation of data input
#         error = False
#         if not validate_indicator(data):
#             self._add_error(ErrorCodes.e5010.value % data)
#             error = True
#         if not isinstance(data_type_enum, IndicatorType):
#             self._add_error(ErrorCodes.e5011.value % data_type_enum)
#             error = True
#
#         if not error:
#             filter_type = data_type_enum.value
#
#             ro = RequestObject(filter_type, data)
#             ro.set_owner_allowed(properties.indicator_owner_allowed)
#             ro.set_resource_pagination(properties.resource_pagination)
#             ro.set_request_uri(properties.indicator_path, [data_type_enum.value, data])
#             ro.set_resource_key(properties.resource_key)
#             self._add_request_objects(ro)
#
#     def add_owner(self, data):
#         """ """
#         if isinstance(data, list):
#             self._owners.extend(data)
#         else:
#             self._owners.append(data)
#
#     def add_security_label(self, data):
#         """ """
#         properties = self._properties_class()
#         if not isinstance(data, str):
#             self._add_error(ErrorCodes.e4070.value % data)
#         else:
#             filter_type = 'security_label'
#             ro = RequestObject(filter_type, data)
#             ro.set_owner_allowed(properties.security_label_owner_allowed)
#             ro.set_resource_pagination(properties.resource_pagination)
#             ro.set_request_uri(properties.security_label_path, [data])
#             ro.set_resource_key(properties.resource_key)
#             self._add_request_objects(ro)
#
#     def add_signature_id(self, data):
#         """ """
#         properties = self._properties_class()
#         # validation of data input
#         if not validate_int(data):
#             self._add_error(ErrorCodes.e4040.value % data)
#         else:
#             filter_type = 'signature_id'
#             ro = RequestObject(filter_type, data)
#             ro.set_owner_allowed(properties.signature_owner_allowed)
#             ro.set_resource_pagination(properties.resource_pagination)
#             ro.set_request_uri(properties.signature_path, [data])
#             ro.set_resource_key(properties.resource_key)
#             self._add_request_objects(ro)
#
#     def add_tag(self, data):
#         """ """
#         properties = self._properties_class()
#         if not isinstance(data, str):
#             self._add_error(ErrorCodes.e4080.value % data)
#         else:
#             filter_type = 'tag'
#             ro = RequestObject(filter_type, data)
#             ro.set_owner_allowed(properties.tag_owner_allowed)
#             ro.set_resource_pagination(properties.resource_pagination)
#             ro.set_request_uri(properties.tag_path, [data])
#             ro.set_resource_key(properties.resource_key)
#             self._add_request_objects(ro)
#
#     def add_threat_id(self, data):
#         """ """
#         properties = self._properties_class()
#         # validation of data input
#         if not validate_int(data):
#             self._add_error(ErrorCodes.e4050.value % data)
#         else:
#             filter_type = 'threat_id'
#             ro = RequestObject(filter_type, data)
#             ro.set_owner_allowed(properties.threat_owner_allowed)
#             ro.set_resource_pagination(properties.resource_pagination)
#             ro.set_request_uri(properties.threat_path, [data])
#             ro.set_resource_key(properties.resource_key)
#             self._add_request_objects(ro)
#
#     def add_victim_id(self, data):
#         """ """
#         properties = self._properties_class()
#         # validation of data input
#         if not validate_int(data):
#             self._add_error(ErrorCodes.e4060.value % data)
#         else:
#             filter_type = 'victim_id'
#             ro = RequestObject(filter_type, data)
#             ro.set_owner_allowed(properties.victim_owner_allowed)
#             ro.set_resource_pagination(properties.resource_pagination)
#             ro.set_request_uri(properties.victim_path, [data])
#             ro.set_resource_key(properties.resource_key)
#             self._add_request_objects(ro)
#
#     def get_owners(self):
#         """ """
#         return self._owners

