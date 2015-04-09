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
        properties = VictimsProperties()
        self._http_method = properties.http_method
        self._owner_allowed = properties.base_owner_allowed
        self._resource_pagination = properties.resource_pagination
        self._request_uri = properties.base_path
        self._resource_type = properties.resource_type


class VictimFilterObject(FilterObject):
    """ """
    def __init__(self):
        """ """
        super(VictimFilterObject, self).__init__()
        self._owners = []

        # define properties for resource type
        self._properties = VictimsProperties()
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

    # special case for indicator associations
    def filter_associations(self, base_resource_type, identifier):
        """Get victims associated with base resource object
        GET /v2/groups/adversaries/747266/victims

        GET /v2/indicators/addresses/4.3.2.1/victims

        """
        base_properties = ResourceProperties[base_resource_type.name].value()
        print(base_resource_type)

        request_uri = base_properties.base_path + '/'
        request_uri += str(identifier)
        request_uri += '/victims'

        description = 'Get victim associations for %s resource (%s).' % (
            base_resource_type.name.lower(), str(identifier))

        filter_type = 'victim association'
        ro = RequestObject(
            filter_type, '%s|%s' % (base_resource_type.name.lower(), identifier))
        ro.set_description(description)
        ro.set_owner_allowed(False)
        ro.set_resource_pagination(True)
        ro.set_request_uri(request_uri)
        ro.set_resource_type(ResourceType.VICTIMS)
        self._add_request_objects(ro)

