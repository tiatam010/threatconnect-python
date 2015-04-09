""" standard """
import types

""" custom """
from threatconnect.AttributeDef import AttributeDef
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.ErrorCodes import ErrorCodes
from threatconnect.RequestObject import RequestObject
from threatconnect.Validate import get_resource_type, get_resource_group_type


#
# matched filters
#
def add_matched_filter(self, data):
    """ """
    if data is not None:
        self._matched_filters.append(data)


def get_matched_filters(self):
    """ """
    return self._matched_filters

attr = AttributeDef('_matched_filters')
attr.set_method_get('get_matched_filters')
attr.set_method_set('add_matched_filter')
attr.set_type(types.ListType)
matched_filters_attr = attr


#
# body
#
def get_body(self):
    """ """
    return self._body


def set_body(self, data):
    """ """
    self._body = data

attr = AttributeDef('_body')
attr.add_api_name('body')
attr.set_required(True)
attr.set_writable(True)
attr.set_method_get('get_body')
attr.set_method_set('set_body')
body_attr = attr


#
# confidence
#
def get_confidence(self):
    """ """
    return self._confidence


def set_confidence(self, data):
    """ """
    if self._stage is 'new':
        self._api_action = 'update'

    if isinstance(data, int):
        if 0 <= data <= 100:
            self._confidence = data
        else:
            self.add_error_msg(ErrorCodes.e10010.value % data)
            # self._confidence = None
    else:
        self.add_error_msg(ErrorCodes.e10011.value % data)
        # self._confidence = None

attr = AttributeDef('_confidence')
attr.add_api_name('confidence')
attr.set_required(False)
attr.set_writable(True)
attr.set_type(types.NoneType)
attr.set_method_get('get_confidence')
attr.set_method_set('set_confidence')
confidence_attr = attr


#
# date
#
def get_date(self):
    """ """
    return self._date


def set_date(self, data):
    """ """
    self._date = data

attr = AttributeDef('_date')
attr.add_api_name('date')
attr.set_required(True)
attr.set_writable(True)
attr.set_type(types.NoneType)
attr.set_method_get('get_date')
attr.set_method_set('set_date')
date_attr = attr


#
# date_added
#
def get_date_added(self):
    """ """
    return self._date_added


def set_date_added(self, data):
    """ """
    self._date_added = data

attr = AttributeDef('_date_added')
attr.add_api_name('dateAdded')
attr.set_writable(False)
attr.set_type(types.NoneType)
attr.set_method_get('get_date_added')
attr.set_method_set('set_date_added')
date_added_attr = attr


#
# description
#
def get_description(self):
    """ """
    return self._description


def set_description(self, data):
    """ """
    self._description = data.encode('ascii', 'ignore')

attr = AttributeDef('_description')
attr.add_api_name('description')
attr.set_required(False)
attr.set_writable(False)
attr.set_method_get('get_description')
attr.set_method_set('set_description')
description_attr = attr


#
# displayed
#
def get_displayed(self):
    """ """
    return self._displayed


def set_displayed(self, data):
    """ """
    self._displayed = data

attr = AttributeDef('_displayed')
attr.add_api_name('displayed')
attr.set_required(False)
attr.set_writable(False)
attr.set_method_get('get_displayed')
attr.set_method_set('set_displayed')
displayed_attr = attr


#
# dns_active
#
def get_dns_active(self):
    """ """
    return self._dns_active


def set_dns_active(self, data):
    """ """
    self._dns_active = data

attr = AttributeDef('_dns_active')
attr.add_api_name('dnsActive')
attr.set_required(False)
attr.set_writable(True)
attr.set_method_get('get_dns_active')
attr.set_method_set('set_dns_active')
dns_active_attr = attr


# #
# # download
# #
# def get_download(self):
#     """ """
#     return self._download
#
#
# def download(self):
#     """ """
#     # request_uri = '/v2/groups/signatures/%s/download' % self._id
#     # # api_response = ThreatConnect._api_request(request_uri, request_payload={}, http_method='GET')
#     #
#     # if api_response.status_code == 200:
#     #     self._download = api_response.content
#     pass
#
# attr = AttributeDef('_download')
# attr.add_api_name('download')
# attr.set_required(False)
# attr.set_writable(False)
# attr.set_method_get('get_download')
# attr.set_method_set('download')
# download_attr = attr


#
# event_date
#
def get_event_date(self):
    """ """
    return self._event_date


def set_event_date(self, data):
    """ """
    self._event_date = data

attr = AttributeDef('_event_date')
attr.add_api_name('eventDate')
attr.set_required(True)
attr.set_writable(True)
attr.set_method_get('get_event_date')
attr.set_method_set('set_event_date')
event_data_attr = attr


#
# file_name
#
def get_file_name(self):
    """ """
    return self._file_name


def set_file_name(self, data):
    """ """
    self._file_name = data
    if self._stage is 'new':
        self._api_action = 'update'

attr = AttributeDef('_file_name')
attr.add_api_name('fileName')
attr.set_required(True)
attr.set_writable(True)
attr.set_method_get('get_file_name')
attr.set_method_set('set_file_name')
file_name_attr = attr


#
# file_size
#
def get_file_size(self):
    """ """
    return self._file_size


def set_file_size(self, data):
    """ """
    self._file_size = data

attr = AttributeDef('_file_size')
attr.add_api_name('fileSize')
attr.set_required(False)
attr.set_writable(False)
attr.set_method_get('get_file_size')
attr.set_method_set('set_file_size')
file_size_attr = attr


#
# file_text
#
def get_file_text(self):
    """ """
    return self._file_text


def set_file_text(self, data):
    """ """
    self._file_text = data

attr = AttributeDef('_file_text')
attr.add_api_name('fileText')
attr.set_required(True)
attr.set_writable(True)
attr.set_method_get('get_file_text')
attr.set_method_set('set_file_text')
file_text_attr = attr


#
# file_type
#
def get_file_type(self):
    """ """
    return self._file_type


def set_file_type(self, data):
    """ """
    self._file_type = data

attr = AttributeDef('_file_type')
attr.add_api_name('fileType')
attr.set_required(True)
attr.set_writable(True)
attr.set_method_get('get_file_type')
attr.set_method_set('set_file_type')
file_type_attr = attr


#
# from
#
def get_from(self):
    """ """
    return self._from


def set_from(self, data):
    """ """
    self._from = data

attr = AttributeDef('_from')
attr.add_api_name('from')
attr.set_required(True)
attr.set_writable(True)
attr.set_method_get('get_from')
attr.set_method_set('set_from')
from_attr = attr


#
# header
#
def get_header(self):
    """ """
    return self._header


def set_header(self, data):
    """ """
    self._header = data

attr = AttributeDef('_header')
attr.add_api_name('header')
attr.set_required(True)
attr.set_writable(True)
attr.set_method_get('get_header')
attr.set_method_set('set_header')
header_attr = attr


#
# id
#
def get_id(self):
    """ """
    return self._id


def set_id(self, data):
    """ """
    self._id = data

attr = AttributeDef('_id')
attr.add_api_name('id')
attr.set_required(False)
attr.set_writable(False)
attr.set_method_get('get_id')
attr.set_method_set('set_id')
id_attr = attr


#
# indicator
#
def get_indicator(self):
    """ """
    return self._indicator


def set_indicator(self, data):
    """ """
    self._indicator = data

attr = AttributeDef('_indicator')
attr.add_api_name('indicator')
attr.set_required(True)
attr.set_writable(False)
attr.set_method_get('get_indicator')
attr.set_method_set('set_indicator')
indicator_attr = attr


#
# last_modified
#
def get_last_modified(self):
    """ """
    return self._last_modified


def set_last_modified(self, data):
    """ """
    self._last_modified = data

attr = AttributeDef('_last_modified')
attr.add_api_name('lastModified')
attr.set_required(False)
attr.set_writable(False)
attr.set_method_get('get_last_modified')
attr.set_method_set('set_last_modified')
last_modified_attr = attr


#
# name
#
def get_name(self):
    """ """
    return self._name


def set_name(self, data):
    """ """
    self._name = data
    if self._stage is 'new':
        self._api_action = 'update'

attr = AttributeDef('_name')
attr.add_api_name('name')
attr.set_required(True)
attr.set_writable(True)
attr.set_method_get('get_name')
attr.set_method_set('set_name')
name_attr = attr


#
# nationality
#
def get_nationality(self):
    """ """
    return self._nationality


def set_nationality(self, data):
    """ """
    self._nationality = data

attr = AttributeDef('_nationality')
attr.add_api_name('nationality')
attr.set_required(False)
attr.set_writable(False)
attr.set_method_get('get_nationality')
attr.set_method_set('set_nationality')
nationality_attr = attr


#
# get_org
#
def get_org(self):
    """ """
    return self._org


def set_org(self, data):
    """ """
    self._org = data

attr = AttributeDef('_org')
attr.add_api_name('org')
attr.set_required(False)
attr.set_writable(False)
attr.set_method_get('get_org')
attr.set_method_set('set_org')
org_attr = attr


#
# owner_name
#
def get_owner_name(self):
    """ """
    return self._owner_name


def set_owner_name(self, data):
    """ """
    self._owner_name = data

attr = AttributeDef('_owner_name')
attr.add_api_name('ownerName')
attr.set_required(False)
attr.set_writable(False)
attr.set_method_get('get_owner_name')
attr.set_method_set('set_owner_name')
owner_name_attr = attr


#
# path
#
def get_path(self):
    """ """
    return self._path


def set_path(self, data):
    """ """
    self._path = data

attr = AttributeDef('_path')
attr.add_api_name('path')
attr.set_required(False)
attr.set_writable(True)
attr.set_method_get('get_path')
attr.set_method_set('set_path')
path_attr = attr


#
# rating
#
def get_rating(self):
    """ """
    return self._rating


def set_rating(self, data):
    """ """
    if self._stage is 'new':
        self._api_action = 'update'

    self._rating = data

attr = AttributeDef('_rating')
attr.add_api_name('rating')
# TODO: fix this
# attr.add_api_name('threatAssessRating')
attr.set_required(False)
attr.set_writable(True)
attr.set_method_get('get_rating')
attr.set_method_set('set_rating')
rating_attr = attr


#
# score
#
def get_score(self):
    """ """
    return self._score


def set_score(self, data):
    """ """
    self._score = data

attr = AttributeDef('_score')
attr.add_api_name('score')
attr.set_required(False)
attr.set_writable(False)
attr.set_method_get('get_score')
attr.set_method_set('set_score')
score_attr = attr


#
# source
#
def get_source(self):
    """ """
    return self._source


def set_source(self, data):
    """ """
    self._source = data

attr = AttributeDef('_source')
attr.add_api_name('source')
attr.set_required(False)
attr.set_writable(False)
attr.set_method_get('get_source')
attr.set_method_set('set_source')
source_attr = attr


#
# subject
#
def get_subject(self):
    """ """
    return self._subject


def set_subject(self, data):
    """ """
    self._subject = data

attr = AttributeDef('_subject')
attr.add_api_name('subject')
attr.set_required(True)
attr.set_writable(True)
attr.set_method_get('get_subject')
attr.set_method_set('set_subject')
subject_attr = attr


#
# suborg
#
def get_suborg(self):
    """ """
    return self._suborg


def set_suborg(self, data):
    """ """
    self._suborg = data

attr = AttributeDef('_suborg')
attr.add_api_name('suborg')
attr.set_required(False)
attr.set_writable(False)
attr.set_method_get('get_suborg')
attr.set_method_set('set_suborg')
suborg_attr = attr


#
# to
#
def get_to(self):
    """ """
    return self._to


def set_to(self, data):
    """ """
    self._to = data

attr = AttributeDef('_to')
attr.add_api_name('to')
attr.set_required(False)
attr.set_writable(True)
attr.set_method_get('get_to')
attr.set_method_set('set_to')
to_attr = attr


#
# type
#
def get_type(self):
    """ """
    return self._type


def set_type(self, data):
    """ """
    self._type = data

    if 100 <= self._resource_type.value <= 299:
        self._resource_type = get_resource_group_type(self._type)


attr = AttributeDef('_type')
attr.add_api_name('type')
attr.set_required(False)
attr.set_writable(False)
attr.set_method_get('get_type')
attr.set_method_set('set_type')
type_attr = attr


#
# value
#
def get_value(self):
    """ """
    return self._value


def set_value(self, data):
    """ """
    self._value = data

attr = AttributeDef('_value')
attr.add_api_name('value')
attr.set_required(False)
attr.set_writable(True)
attr.set_method_get('get_value')
attr.set_method_set('set_value')
value_attr = attr


#
# web_link
#
def get_web_link(self):
    """ """
    return self._web_link


def set_web_link(self, data):
    """ """
    self._web_link = data

attr = AttributeDef('_web_link')
attr.add_api_name('webLink')
attr.set_required(False)
attr.set_writable(False)
attr.set_method_get('get_web_link')
attr.set_method_set('set_web_link')
web_link_attr = attr


#
# whois_active
#
def get_whois_active(self):
    """ """
    return self._whois_active


def set_whois_active(self, data):
    """ """
    self._whois_active = data

attr = AttributeDef('_whois_active')
attr.add_api_name('whoisActive')
attr.set_required(False)
attr.set_writable(True)
attr.set_method_get('get_whois_active')
attr.set_method_set('set_whois_active')
whois_active_attr = attr


#
# work_location
#
def get_work_location(self):
    """ """
    return self._work_location


def set_work_location(self, data):
    """ """
    self._work_location = data

attr = AttributeDef('_work_location')
attr.add_api_name('workLocation')
attr.set_required(False)
attr.set_writable(False)
attr.set_method_get('get_work_location')
attr.set_method_set('set_work_location')
work_location_attr = attr


#
# address (indicator)
#
def set_address(self, data):
    """ """
    self._indicator = data
    self._type = ResourceType.EMAIL_ADDRESSES

    # update the resource type
    self._resource_type = get_resource_type(self._indicator)

attr = AttributeDef('_indicator')
attr.add_api_name('address')
attr.set_required(True)
attr.set_writable(True)
attr.set_method_get('get_indicator')
attr.set_method_set('set_address')
address_attr = attr


#
# hash (indicator)
#
def set_hash(self, data):
    """ """
    self._indicator = data
    self._type = ResourceType.FILES

    # update the resource type
    self._resource_type = get_resource_type(self._indicator)

attr = AttributeDef('_indicator')
attr.add_api_name('md5')
attr.add_api_name('sha1')
attr.add_api_name('sha256')
attr.set_required(True)
attr.set_writable(True)
attr.set_method_get('get_indicator')
attr.set_method_set('set_hash')
hash_attr = attr


#
# hostname (indicator)
#
def set_hostname(self, data):
    """ """
    self._indicator = data
    self._type = ResourceType.HOSTS

    # update the resource type
    self._resource_type = get_resource_type(self._indicator)

attr = AttributeDef('_indicator')
attr.add_api_name('hostName')
attr.set_required(True)
attr.set_writable(True)
attr.set_method_get('get_indicator')
attr.set_method_set('set_hostname')
hostname_attr = attr


#
# ip (indicator)
#
def set_ip(self, data):
    """ """
    self._indicator = data
    self._type = ResourceType.ADDRESSES

    # update the resource type
    self._resource_type = get_resource_type(self._indicator)

attr = AttributeDef('_indicator')
attr.add_api_name('ip')
attr.set_type(types.NoneType)
attr.set_required(True)
attr.set_writable(True)
attr.set_method_get('get_indicator')
attr.set_method_set('set_ip')
ip_attr = attr


#
# owner (owner name)
#
def set_owner(self, data):
    """ """
    self._owner_name = data['name']

attr = AttributeDef('_owner')
attr.add_api_name('owner')
attr.set_required(False)
attr.set_writable(False)
attr.set_method_get('get_owner')
attr.set_method_set('set_owner')
owner_attr = attr


#
# summary (indicator)
#
def set_summary(self, data):
    """ """
    self._indicator = data

    # update the resource type
    self._resource_type = get_resource_type(self._indicator)

attr = AttributeDef('_indicator')
attr.add_api_name('summary')
attr.set_required(True)
attr.set_writable(False)
attr.set_method_get('get_indicator')
attr.set_method_set('set_summary')
summary_attr = attr


#
# text (indicator)
#
def set_text(self, data):
    """ """
    self._indicator = data

    # update the resource type
    self._resource_type = get_resource_type(self._indicator)

attr = AttributeDef('_indicator')
attr.add_api_name('text')
attr.set_required(True)
attr.set_writable(True)
attr.set_method_get('get_indicator')
attr.set_method_set('set_text')
text_attr = attr


#
# url (indicator)
#
def set_url(self, data):
    """ """
    self._indicator = data
    self._type = ResourceType.URLS

    # update the resource type
    self._resource_type = get_resource_type(self._indicator)

attr = AttributeDef('_url')
attr.add_api_name('url')
attr.set_required(True)
attr.set_writable(True)
attr.set_method_get('get_url')
attr.set_method_set('set_url')
url_attr = attr


#
# file upload
#
def upload(self, data, update=False):
    """
    POST|PUT /v2/groups/documents/<DOCUMENT ID>/upload
    Host: api.threatconnect.com
    Content-Type:  application/octet-stream
    """

    if update:
        http_method = 'PUT'
    else:
        http_method = 'POST'

    # build request object dict so that the identifier can be
    # pulled at the very end.  This is important due to using
    # temp ids when creating a resource.
    self._urd = {
        'name1': 'Document Upload',
        'name2_method': self.get_id,
        'body': data,
        'content_type': 'application/octet-stream',
        'description': 'Document Upload to document resource (%s)',
        'http_method': http_method,
        'request_uri_path': '/v2/groups/documents/%s/upload',
        'identifier_method': self.get_id,
        'owner_allowed': False,
        'resource_pagination': False,
        'resource_type': ResourceType.DOCUMENTS}


def upload_request(self):
    """ """
    # build request object
    request_object = RequestObject(self._urd['name1'], self._urd['name2_method']())
    request_object.set_body(self._urd['body'])
    request_object.set_content_type(self._urd['content_type'])
    request_object.set_description(
        self._urd['description'] % self._urd['identifier_method']())
    request_object.set_http_method(self._urd['http_method'])
    request_object.set_request_uri(
        self._urd['request_uri_path'] % self._urd['identifier_method']())
    request_object.set_owner_allowed(self._urd['owner_allowed'])
    request_object.set_resource_pagination(self._urd['resource_pagination'])
    request_object.set_resource_type(self._urd['resource_type'])

    return request_object

attr = AttributeDef('_urd')
attr.add_api_name('upload')
attr.set_required(False)
attr.set_writable(False)
attr.set_method_get('upload')
attr.set_method_set('upload_request')
upload_attr = attr


#
# file download
#
def download(self):
    """
    GET /v2/groups/documents/<DOCUMENT ID>/download
    Host: api.threatconnect.com
    Content-Type:  application/octet-stream
    """

    # build request object dict so that the identifier can be
    # pulled at the very end.  This is important due to using
    # temp ids when creating a resource.
    self._drd = {
        'name1': 'Document Download',
        'name2_method': self.get_id,
        'content_type': 'application/octet-stream',
        'description': 'Document download of document resource (%s)',
        'http_method': 'GET',
        'request_uri_path': '/v2/groups/documents/%s/download',
        'identifier_method': self.get_id,
        'owner_allowed': False,
        'resource_pagination': False,
        'resource_type': ResourceType.DOCUMENTS}


def download_request(self):
    """ """
    # build request object
    request_object = RequestObject(self._drd['name1'], self._drd['name2_method']())
    request_object.set_content_type(self._drd['content_type'])
    request_object.set_description(
        self._drd['description'] % self._drd['identifier_method']())
    request_object.set_http_method(self._drd['http_method'])
    request_object.set_request_uri(
        self._drd['request_uri_path'] % self._drd['identifier_method']())
    request_object.set_owner_allowed(self._drd['owner_allowed'])
    request_object.set_resource_pagination(self._drd['resource_pagination'])
    request_object.set_resource_type(self._drd['resource_type'])

    return request_object

attr = AttributeDef('_drd')
attr.add_api_name('download')
attr.set_required(False)
attr.set_writable(False)
attr.set_method_get('download')
attr.set_method_set('download_request')
download_attr = attr
