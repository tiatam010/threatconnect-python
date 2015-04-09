""" standard """
import types

""" custom """
from threatconnect import FilterMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Properties.FileOccurrencesProperties import FileOccurrencesProperties
from threatconnect.Resource import Resource
from threatconnect.FilterObject import FilterObject

""" Note: PEP 8 intentionally ignored for variable/methods to match API standard. """


class FileOccurrences(Resource):
    """ """
    def __init__(self, tc_obj):
        """ """
        super(FileOccurrences, self).__init__(tc_obj)
        self._filter_class = FileOccurrenceFilterObject

        # set properties
        properties = FileOccurrencesProperties()
        self._http_method = properties.http_method
        self._owner_allowed = properties.base_owner_allowed
        self._resource_pagination = properties.resource_pagination
        self._request_uri = properties.base_path
        self._resource_type = properties.resource_type

    def add(self, file_hash):
        """ """
        # set properties
        properties = FileOccurrencesProperties(PropertiesAction.POST)
        self._http_method = properties.http_method
        self._owner_allowed = False
        self._resource_pagination = False
        self._request_uri = properties.post_path % file_hash

        # resource object
        self._resource_object = properties.resource_object

        return self._resource_object


class FileOccurrenceFilterObject(FilterObject):
    """ """

    def __init__(self):
        """ """
        super(FileOccurrenceFilterObject, self).__init__()
        self._owners = []

        # define properties for resource type
        self._properties = FileOccurrencesProperties()
        self._owner_allowed = self._properties.base_owner_allowed
        self._resource_pagination = self._properties.resource_pagination
        self._request_uri = self._properties.base_path
        self._resource_type = self._properties.resource_type

        #
        # add_obj filter methods
        #
        for method_name in self._properties.filters:
            method = getattr(FilterMethods, method_name)
            setattr(self, method_name, types.MethodType(method, self))

