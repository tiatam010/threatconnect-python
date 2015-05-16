""" standard """
import types

""" custom """
from threatconnect import FilterMethods
from threatconnect.Config.ResourceProperties import ResourceProperties
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Properties.VictimsProperties import VictimsProperties
from threatconnect.RequestObject import RequestObject
from threatconnect.Resource import Resource
from threatconnect.FilterObject import FilterObject

""" Note: PEP 8 intentionally ignored for variable/methods to match API standard. """


class Victims(Resource):
    """ """
    def __init__(self, tc_obj):
        """ """
        super(Victims, self).__init__(tc_obj)
        self._filter_class = VictimFilterObject

        # set properties
        properties = VictimsProperties(base_uri=self.base_uri)
        self._resource_type = properties.resource_type

        # create default request object for non-filtered requests
        self._request_object = RequestObject('victims', 'default')
        self._request_object.set_http_method(properties.http_method)
        self._request_object.set_owner_allowed(properties.base_owner_allowed)
        self._request_object.set_request_uri(properties.base_path)
        self._request_object.set_resource_pagination(properties.resource_pagination)
        self._request_object.set_resource_type(properties.resource_type)


class VictimFilterObject(FilterObject):
    """ """
    def __init__(self, base_uri, tcl):
        """ """
        super(VictimFilterObject, self).__init__(base_uri, tcl)
        self._owners = []

        # define properties for resource type
        self._properties = VictimsProperties(base_uri=self.base_uri)
        self._resource_type = self._properties.resource_type

        # create default request object for filtered request with only owners
        self._request_object = RequestObject('victims', 'default')
        self._request_object.set_http_method(self._properties.http_method)
        self._request_object.set_owner_allowed(self._properties.base_owner_allowed)
        self._request_object.set_request_uri(self._properties.base_path)
        self._request_object.set_resource_pagination(self._properties.resource_pagination)
        self._request_object.set_resource_type(self._properties.resource_type)

        #
        # add_obj filter methods
        #
        for method_name in self._properties.filters:
            method = getattr(FilterMethods, method_name)
            setattr(self, method_name, types.MethodType(method, self))

    # special case for indicator associations
    def filter_associations(self, base_resource_type, identifier):
        """Get victims associated with base resource object
        GET /v2/groups/adversaries/747266/victims

        GET /v2/indicators/addresses/4.3.2.1/victims

        """
        base_properties = ResourceProperties[base_resource_type.name].value()

        request_uri = base_properties.base_path + '/'
        request_uri += str(identifier)
        request_uri += '/victims'

        description = 'Get victim associations for {0} resource ({1}).'.format(
            base_resource_type.name.lower(), str(identifier))

        filter_type = 'victim association'
        ro = RequestObject(
            filter_type, '{0}|{1}'.format(base_resource_type.name.lower(), identifier))
        ro.set_description(description)
        ro.set_owner_allowed(False)
        ro.set_resource_pagination(True)
        ro.set_request_uri(request_uri)
        ro.set_resource_type(ResourceType.VICTIMS)
        self._add_request_objects(ro)

