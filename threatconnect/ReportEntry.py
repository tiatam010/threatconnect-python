""" standard """
from pprint import pformat

""" custom """
from threatconnect.DataFormatter import format_header, format_item


class ReportEntry(object):
    """ """

    def __init__(self):
        """ """
        self._action = None
        self._data = []
        self._resource_type = None
        self._status = None
        self._status_code = None

    def add_data(self, data):
        """ """
        self._data.append(data)

    def set_action(self, data):
        """ """
        self._action = data

    def set_resource_type(self, data_enum):
        """ """
        self._resource_type = data_enum

    def set_status(self, data):
        """ """
        self._status = data

    def set_status_code(self, data_int):
        """ """
        self._status_code = data_int

    @property
    def action(self):
        """ """
        return self._action

    @property
    def data(self):
        """ """
        return self._data

    @property
    def resource_type(self):
        """ """
        return self._resource_type

    @property
    def status(self):
        """ """
        return self._status

    @property
    def status_code(self):
        """ """
        return self._status_code

    def __str__(self):
        """ """
        obj_str = format_header('%s Entry:' % self._resource_type.name)
        obj_str += format_item('Action', self._action)
        obj_str += format_item('Status', self._status)
        obj_str += format_item('Data', '')
        for data in self._data:
            for k, v in data.items():
                obj_str += format_item('%s' % k, v, 1)

        return obj_str

