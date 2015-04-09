""" standard """
import time
import urllib

""" third-party """
import dateutil.parser

""" custom """
from Config.FilterOperator import FilterOperator
from Config.IndicatorType import IndicatorType
from Config.ResourceProperties import ResourceProperties
from Config.ResourceRegexes import indicators_regex
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.ErrorCodes import ErrorCodes
from threatconnect.PostFilterObject import PostFilterObject
from threatconnect.RequestObject import RequestObject
from threatconnect.Validate import validate_indicator


def _get_resource_type(indicator):
    """ """
    for indicator_type, regex in indicators_regex.items():
        for rex in regex:
            if rex.match(indicator):
                return ResourceType[indicator_type]
    return None


def add_adversary_id(self, data_int, asset_id=None):
    """ """
    if asset_id is not None:
        resource_type = ResourceType(self._resource_type.value - 5)
        properties = ResourceProperties[resource_type.name].value()
        uri_data = [data_int, asset_id]
    else:
        properties = self._properties
        uri_data = [data_int]

    # validation of data input
    if not isinstance(data_int, int):
        self._add_error(ErrorCodes.e4000.value % data_int)
        self._error = True
    else:
        filter_type = 'adversary_id'
        ro = RequestObject(filter_type, data_int)
        ro.set_owner_allowed(properties.adversary_owner_allowed)
        ro.set_resource_pagination(properties.resource_pagination)
        ro.set_request_uri(properties.adversary_path, uri_data)
        ro.set_resource_type(properties.resource_type)
        self._add_request_objects(ro)


def add_email_id(self, data_int, asset_id=None):
    """ """
    if asset_id is not None:
        resource_type = ResourceType(self._resource_type.value - 5)
        properties = ResourceProperties[resource_type.name].value()
        uri_data = [data_int, asset_id]
    else:
        properties = self._properties
        uri_data = [data_int]

    # validation of data input
    if not isinstance(data_int, int):
        self._add_error(ErrorCodes.e4010.value % data_int)
        self._error = True
    else:
        filter_type = 'email_id'
        ro = RequestObject(filter_type, data_int)
        ro.set_owner_allowed(properties.email_owner_allowed)
        ro.set_resource_pagination(properties.resource_pagination)
        ro.set_request_uri(properties.email_path, uri_data)
        ro.set_resource_type(properties.resource_type)
        self._add_request_objects(ro)


def add_hash(self, data, data_int=None):
    """ """
    if data_int is not None:
        resource_type = ResourceType(self._resource_type.value - 5)
        properties = ResourceProperties[resource_type.name].value()
    else:
        properties = self._properties
    # validation of data input
    if not isinstance(data, str):
        self._add_error(ErrorCodes.e4020.value % data)
        self._error = True
    else:
        filter_type = 'hash'
        ro = RequestObject(filter_type, data)
        ro.set_owner_allowed(properties.hash_owner_allowed)
        ro.set_resource_pagination(properties.resource_pagination)
        if data_int is not None:
            ro.set_request_uri(properties.hash_path, [data, data_int])
        else:
            ro.set_request_uri(properties.hash_path, [data])
        ro.set_resource_type(properties.resource_type)
        self._add_request_objects(ro)


def add_id(self, data_int, asset_id=None):
    """ """
    resource_type = ResourceType(self._resource_type.value - 5)
    properties = ResourceProperties[resource_type.name].value()
    if asset_id is not None:
        # resource_type = ResourceType(self._resource_type.value - 5)
        # properties = ResourceProperties[resource_type.name].value()
        uri_data = [data_int, asset_id]
    else:
        # properties = self._properties
        uri_data = [data_int]

    # validation of data input
    if not isinstance(data_int, int):
        self._add_error(ErrorCodes.e4020.value % data_int)
        self._error = True
    else:
        filter_type = 'id'
        if asset_id is not None:
            filter_values = '%s-%s' % (data_int, asset_id)
        else:
            filter_values = data_int
        ro = RequestObject(filter_type, filter_values)
        ro.set_owner_allowed(properties.id_owner_allowed)
        ro.set_resource_pagination(properties.resource_pagination)
        ro.set_request_uri(properties.id_path, uri_data)
        ro.set_resource_type(properties.resource_type)
        self._add_request_objects(ro)


def add_id_signature(self, data_int, download=False):
    """ """
    resource_type = ResourceType(self._resource_type.value - 5)
    properties = ResourceProperties[resource_type.name].value()
    uri_data = [data_int]

    # validation of data input
    if not isinstance(data_int, int):
        self._add_error(ErrorCodes.e4020.value % data_int)
        self._error = True
    else:
        filter_type = 'id'
        ro = RequestObject(filter_type, data_int)
        ro.set_owner_allowed(properties.id_owner_allowed)
        ro.set_resource_pagination(properties.resource_pagination)
        ro.set_request_uri(properties.id_path, uri_data)
        ro.set_resource_type(properties.resource_type)

        # add_obj download
        if download:
            ro.set_download(True)

        self._add_request_objects(ro)


def add_incident_id(self, data_int, asset_id=None):
    """ """
    if asset_id is not None:
        resource_type = ResourceType(self._resource_type.value - 5)
        properties = ResourceProperties[resource_type.name].value()
        uri_data = [data_int, asset_id]
    else:
        properties = self._properties
        uri_data = [data_int]

    # validation of data input
    if not isinstance(data_int, int):
        self._add_error(ErrorCodes.e4030.value % data_int)
        self._error = True
    else:
        filter_type = 'incident_id'
        ro = RequestObject(filter_type, data_int)
        ro.set_owner_allowed(properties.incident_owner_allowed)
        ro.set_resource_pagination(properties.resource_pagination)
        ro.set_request_uri(properties.incident_path, uri_data)
        ro.set_resource_type(properties.resource_type)
        self._add_request_objects(ro)


def add_indicator(self, data, data_type_enum=None):
    """ """
    if data_type_enum is None:
        # use indicator value to get the resource type
        data_type_enum = _get_resource_type(data)
    else:
        # indicator type provided
        if isinstance(data_type_enum, IndicatorType):
            data_type_enum = ResourceType(data_type_enum.value)

    error = False
    # validation indicator
    if not validate_indicator(data):
        self._add_error(ErrorCodes.e5010.value % data)
        self._error = True
        error = True

    # validation resource type
    if not isinstance(data_type_enum, ResourceType):
        self._add_error(ErrorCodes.e5011.value % data_type_enum)
        self._error = True
        error = True

    if not error:
        # get properties for indicator
        # (e.g ADDRESSES is 515 and ADDRESS is 510.
        indicator_resource_type = ResourceType(data_type_enum.value - 5)
        indicator_properties = ResourceProperties[indicator_resource_type.name].value()
        indicator_type = indicator_properties.resource_uri_attribute

        # determine properties
        indicator_resources = [
            'INDICATORS', 'ADDRESSES', 'EMAIL_ADDRESSES', 'FILES', 'HOSTS', 'URLS']
        if self._properties.resource_type.name in indicator_resources:
            # if the resource type is one of the above use the properties of that indicator
            properties = indicator_properties
        else:
            # otherwise use the properties of the resource
            properties = self._properties

        # url
        if data_type_enum == ResourceType.URLS:
            data = urllib.quote(data, safe='~')

        filter_type = data_type_enum.name.lower()

        ro = RequestObject(filter_type, data)
        ro.set_owner_allowed(properties.indicator_owner_allowed)
        ro.set_resource_pagination(properties.resource_pagination)
        ro.set_request_uri(
            properties.indicator_path, [indicator_type, data])
        ro.set_resource_type(properties.resource_type)
        self._add_request_objects(ro)


def add_name(self, data):
    """ """
    resource_type = ResourceType(self._resource_type.value - 5)
    properties = ResourceProperties[resource_type.name].value()
    # validation of data input
    if not isinstance(data, str):
        self._add_error(ErrorCodes.e4080.value % data)
        self._error = True
    else:
        filter_type = 'name'
        ro = RequestObject(filter_type, data)
        ro.set_owner_allowed(properties.name_owner_allowed)
        ro.set_resource_pagination(properties.resource_pagination)
        ro.set_request_uri(properties.name_path, [data])
        ro.set_resource_type(properties.resource_type)
        self._add_request_objects(ro)


def add_owner(self, data):
    """ """
    if isinstance(data, list):
        self._owners.extend(data)
    else:
        self._owners.append(data)


def add_security_label(self, data):
    """ """
    properties = self._properties
    if not isinstance(data, str):
        self._add_error(ErrorCodes.e4070.value % data)
        self._error = True
    else:
        filter_type = 'security_label'
        ro = RequestObject(filter_type, data)
        ro.set_owner_allowed(properties.security_label_owner_allowed)
        ro.set_resource_pagination(properties.resource_pagination)
        ro.set_request_uri(properties.security_label_path, [data])
        ro.set_resource_type(properties.resource_type)
        self._add_request_objects(ro)


def add_signature_id(self, data_int, asset_id=None):
    """ """
    if asset_id is not None:
        resource_type = ResourceType(self._resource_type.value - 5)
        properties = ResourceProperties[resource_type.name].value()
        uri_data = [data_int, asset_id]
    else:
        properties = self._properties
        uri_data = [data_int]

    # validation of data input
    if not isinstance(data_int, int):
        self._add_error(ErrorCodes.e4040.value % data_int)
        self._error = True
    else:
        filter_type = 'signature_id'
        ro = RequestObject(filter_type, data_int)
        ro.set_owner_allowed(properties.signature_owner_allowed)
        ro.set_resource_pagination(properties.resource_pagination)
        ro.set_request_uri(properties.signature_path, uri_data)
        ro.set_resource_type(properties.resource_type)
        self._add_request_objects(ro)


def add_tag(self, data):
    """ """
    properties = self._properties
    if not isinstance(data, str):
        self._add_error(ErrorCodes.e4080.value % data)
        self._error = True
    else:
        filter_type = 'tag'
        ro = RequestObject(filter_type, data)
        ro.set_owner_allowed(properties.tag_owner_allowed)
        ro.set_resource_pagination(properties.resource_pagination)
        ro.set_request_uri(properties.tag_path, [data])
        ro.set_resource_type(properties.resource_type)
        self._add_request_objects(ro)


def add_threat_id(self, data_int, asset_id=None):
    """ """
    if asset_id is not None:
        resource_type = ResourceType(self._resource_type.value - 5)
        properties = ResourceProperties[resource_type.name].value()
        uri_data = [data_int, asset_id]
    else:
        properties = self._properties
        uri_data = [data_int]

    # validation of data input
    if not isinstance(data_int, int):
        self._add_error(ErrorCodes.e4050.value % data_int)
        self._error = True
    else:
        filter_type = 'threat_id'
        ro = RequestObject(filter_type, data_int)
        ro.set_owner_allowed(properties.threat_owner_allowed)
        ro.set_resource_pagination(properties.resource_pagination)
        ro.set_request_uri(properties.threat_path, uri_data)
        ro.set_resource_type(properties.resource_type)
        self._add_request_objects(ro)


def add_victim_id(self, data_int):
    """ """
    properties = self._properties
    # validation of data input
    if not isinstance(data_int, int):
        self._add_error(ErrorCodes.e4060.value % data_int)
        self._error = True
    else:
        filter_type = 'victim_id'
        ro = RequestObject(filter_type, data_int)
        ro.set_owner_allowed(properties.victim_owner_allowed)
        ro.set_resource_pagination(properties.resource_pagination)
        ro.set_request_uri(properties.victim_path, [data_int])
        ro.set_resource_type(properties.resource_type)
        self._add_request_objects(ro)


def add_date_added(self, data_date, operator=FilterOperator.EQ):
    """ """
    method = 'filter_date_added'
    date_added = data_date
    date_added = dateutil.parser.parse(date_added)
    date_added_seconds = int(time.mktime(date_added.timetuple()))

    filter_name = '%s|%s (%s)' % ('date_added', data_date, date_added_seconds)
    post_filter = PostFilterObject(filter_name)
    post_filter.set_method(method)
    post_filter.set_filter(date_added_seconds)
    post_filter.set_operator(operator)
    self.add_post_filter(post_filter)


def add_file_type(self, data, operator=FilterOperator.EQ):
    """ """
    method = 'filter_file_type'
    filter_name = '%s|%s' % ('file_type', data)

    post_filter = PostFilterObject(filter_name)
    post_filter.set_method(method)
    post_filter.set_filter(data)
    post_filter.set_operator(operator)
    self.add_post_filter(post_filter)


def get_owners(self):
    """ """
    return self._owners


def get_owner_allowed(self):
    """ """
    return self._owner_allowed


def get_resource_pagination(self):
    """ """
    return self._resource_pagination


def get_request_uri(self):
    """ """
    return self._request_uri


def get_resource_type(self):
    """ """
    return self._resource_type
