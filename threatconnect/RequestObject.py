""" custom """
from threatconnect.DataFormatter import format_header, format_item


class RequestObject(object):
    """ """
    def __init__(self, filter_type, filter_value):
        """ """
        self._body = None
        self._content_type = None
        self._description = None
        self._download = False
        self._http_method = 'GET'
        self._modified_since = None
        self._name = '{0}|{1}'.format(filter_type, filter_value)
        self._owner_allowed = None
        self._owners = []
        self._request_uri = None
        self._resource_object_id = None
        self._resource_pagination = None
        self._resource_type = None

    def add_owner(self, data):
        """ """
        self._owners.append(data)

    def set_body(self, data):
        """ """
        self._body = data

    def set_content_type(self, data):
        """ """
        self._content_type = data

    def set_description(self, data):
        """ """
        self._description = data

    def set_download(self, data_bool):
        """ """
        self._download = data_bool

    def set_http_method(self, data):
        """ """
        self._http_method = data

    def set_modified_since(self, data):
        """ """
        self._modified_since = data

    def set_owner_allowed(self, data):
        """ """
        self._owner_allowed = data

    def set_request_uri(self, uri_template, values=None):
        """ """
        if values is None:
            self._request_uri = uri_template
        else:
            self._request_uri = uri_template.format(*values)

    def set_resource_object_id(self, data):
        """ """
        self._resource_object_id = data

    def set_resource_pagination(self, data):
        """ """
        self._resource_pagination = data

    def set_resource_type(self, data_enum):
        """ """
        self._resource_type = data_enum

    @property
    def body(self):
        """ """
        return self._body

    @property
    def content_type(self):
        """ """
        return self._content_type

    @property
    def description(self):
        """ """
        return self._description

    @property
    def download(self):
        """ """
        return self._download

    @property
    def http_method(self):
        """ """
        return self._http_method

    @property
    def modified_since(self):
        """ """
        return self._modified_since

    @property
    def name(self):
        """ """
        return self._name

    @property
    def owners(self):
        """ """
        return self._owners

    @property
    def owner_allowed(self):
        """ """
        return self._owner_allowed

    @property
    def request_uri(self):
        """ """
        return self._request_uri

    @property
    def resource_object_id(self):
        """ """
        return self._resource_object_id

    @property
    def resource_pagination(self):
        """ """
        return self._resource_pagination

    @property
    def resource_type(self):
        """ """
        return self._resource_type

    def __str__(self):
        """ """
        obj_str = format_header('{0} Request Object'.format(self._name))
        printable_items = dict(self.__dict__)
        for key, val in sorted(printable_items.viewitems()):
            obj_str += format_item(key, val)

        return obj_str
