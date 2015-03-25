""" custom """
from threatconnect.DataFormatter import format_header, format_item


class RequestObject(object):
    """ """
    def __init__(self, filter_type, filter_value):
        """ """
        self._download = False
        self._name = '%s|%s' % (filter_type, filter_value)
        self._owner_allowed = None
        self._request_uri = None
        self._resource_pagination = None
        self._resource_type = None

    def set_download(self, data_bool):
        """ """
        self._download = data_bool

    def set_owner_allowed(self, data):
        """ """
        self._owner_allowed = data

    def set_resource_pagination(self, data):
        """ """
        self._resource_pagination = data

    def set_request_uri(self, uri_template, values=None):
        """ """
        # pd('uri_template', uri_template)
        # pd('values', values)
        if values is None:
            self._request_uri = uri_template
        else:
            self._request_uri = uri_template % tuple(values)

    def set_resource_type(self, data_enum):
        """ """
        self._resource_type = data_enum

    @property
    def download(self):
        """ """
        return self._download

    @property
    def name(self):
        """ """
        return self._name

    @property
    def owner_allowed(self):
        """ """
        return self._owner_allowed

    @property
    def request_uri(self):
        """ """
        return self._request_uri

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
        obj_str = format_header('%s Requets Object' % self._name)
        printable_items = dict(self.__dict__)
        for key, val in sorted(printable_items.items()):
            obj_str += format_item(key, val)

        return obj_str
