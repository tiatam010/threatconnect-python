""" custom """
from threatconnect.DataFormatter import format_header, format_item


class PostFilterObject(object):
    """ """
    def __init__(self, name):
        """ """
        self._filter = None
        self._method = None
        self._name = name
        self._operator = None

    def set_filter(self, data):
        """ """
        self._filter = data

    def set_method(self, data):
        """ """
        self._method = data

    def set_operator(self, data_enum):
        """ """
        self._operator = data_enum

    @property
    def filter(self):
        """ """
        return self._filter

    @property
    def method(self):
        """ """
        return self._method

    @property
    def name(self):
        """ """
        return self._name

    @property
    def operator(self):
        """ """
        return self._operator

    def __str__(self):
        """ """
        obj_str = format_header('%s (Post Filter Object)' % self._name)
        printable_items = dict(self.__dict__)
        for key, val in sorted(printable_items.items()):
            obj_str += format_item(key, val)

        return obj_str
