""" standard """
import types
import uuid

""" custom """
from threatconnect import FilterMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Properties.FileOccurrencesProperties import FileOccurrencesProperties
from threatconnect.RequestObject import RequestObject
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
        properties = FileOccurrencesProperties(base_uri=self.base_uri)
        self._http_method = properties.http_method
        self._owner_allowed = properties.base_owner_allowed
        self._resource_pagination = properties.resource_pagination
        self._request_uri = properties.base_path
        self._resource_type = properties.resource_type

    def add(self, file_hash):
        """ """
        # set properties
        properties = FileOccurrencesProperties(
            base_uri=self.base_uri, http_method=PropertiesAction.POST)

        # generate unique temporary id
        resource_id = uuid.uuid4().int

        # resource object
        resource_object = properties.resource_object
        # set resource id
        resource_object.set_id(resource_id)
        # set resource api action
        resource_object.set_phase('add')

        # build request object
        request_object = RequestObject(self._resource_type.name, resource_id)
        request_object.set_description(
            'Adding file occurrence for file hash {0}'.format(file_hash))
        request_object.set_http_method(properties.http_method)
        request_object.set_request_uri(properties.post_path.format(file_hash))
        request_object.set_owner_allowed(True)
        request_object.set_resource_pagination(False)
        request_object.set_resource_type(self._resource_type)

        # add to temporary object storage
        self.add_master_resource_obj(resource_object, resource_id)
        res = self.get_resource_by_id(resource_id)
        request_object.set_resource_object_id(id(res))
        res.set_request_object(request_object)

        # add resource object to parent object
        self.add_obj(res)

        # return object for modification
        return res


class FileOccurrenceFilterObject(FilterObject):
    """ """

    def __init__(self, base_uri, tcl):
        """ """
        super(FileOccurrenceFilterObject, self).__init__(base_uri, tcl)
        self._owners = []

        # define properties for resource type
        self._properties = FileOccurrencesProperties(base_uri=self.base_uri)
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

