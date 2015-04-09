""" std modules """
import types

""" custom modules """
from threatconnect import FilterMethods
from threatconnect.Config.ResourceProperties import ResourceProperties
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.FilterObject import FilterObject
from threatconnect.Properties.GroupsProperties import GroupsProperties
from threatconnect.RequestObject import RequestObject
from threatconnect.Resource import Resource

""" Note: PEP 8 intentionally ignored for variable/methods to match API standard. """


class Groups(Resource):
    """ """

    def __init__(self, tc_obj):
        """ """
        super(Groups, self).__init__(tc_obj)
        self._filter_class = GroupFilterObject

        # set properties
        properties = GroupsProperties()
        self._http_method = properties.http_method
        self._owner_allowed = properties.base_owner_allowed
        self._resource_pagination = properties.resource_pagination
        self._request_uri = properties.base_path
        self._resource_type = properties.resource_type


class GroupFilterObject(FilterObject):
    """ """
    def __init__(self):
        """ """
        super(GroupFilterObject, self).__init__()
        self._owners = []

        # define properties for resource type
        self._properties = GroupsProperties()
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
    def filter_associations(self, base_resource_type, identifier, group_type):
        """Get groups associated with base resource object
        GET /v2/groups/adversaries/747266/groups
        GET /v2/groups/adversaries/747266/groups/adversaries

        GET /v2/indicators/addresses/4.3.2.1/groups
        GET /v2/indicators/addresses/4.3.2.1/groups/adversaries

        GET /v2/victims/628/groups
        GET /v2/victims/628/groups/adversaries
        """
        base_properties = ResourceProperties[base_resource_type.name].value()

        request_uri = base_properties.base_path + '/'
        request_uri += str(identifier)
        if group_type is not None:
            group_properties = ResourceProperties[group_type.name].value()
            irt = group_properties.resource_type

            # update the request uri
            request_uri += '/' + group_properties.resource_uri_attribute
        else:
            request_uri += '/groups'
            irt = ResourceType.GROUPS

        description = 'Get group associations for %s resource (%s).' % (
            base_resource_type.name.lower(), str(identifier))

        filter_type = 'group association'
        ro = RequestObject(
            filter_type, '%s|%s' % (base_resource_type.name.lower(), identifier))
        ro.set_description(description)
        ro.set_owner_allowed(False)
        ro.set_resource_pagination(True)
        ro.set_request_uri(request_uri)
        ro.set_resource_type(irt)
        self._add_request_objects(ro)
