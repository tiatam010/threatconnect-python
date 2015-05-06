""" standard """
import types

""" custom """
from threatconnect import FilterMethods
from threatconnect.Config.ResourceProperties import ResourceProperties
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.VictimAssetType import VictimAssetType
from threatconnect.Properties.VictimAssetsProperties import VictimAssetsProperties
from threatconnect.RequestObject import RequestObject
from threatconnect.Resource import Resource
from threatconnect.FilterObject import FilterObject

""" Note: PEP 8 intentionally ignored for variable/methods to match API standard. """


class VictimAssets(Resource):
    """ """

    def __init__(self, tc_obj):
        """ """
        super(VictimAssets, self).__init__(tc_obj)
        self._filter_class = VictimAssetFilterObject

        # set properties
        properties = VictimAssetsProperties(base_uri=self.base_uri)
        self._resource_type = properties.resource_type

        # create default request object for non-filtered requests
        self._request_object = RequestObject('victimAssets', 'default')
        self._request_object.set_http_method(properties.http_method)
        self._request_object.set_owner_allowed(properties.base_owner_allowed)
        self._request_object.set_request_uri(properties.base_path)
        self._request_object.set_resource_pagination(properties.resource_pagination)
        self._request_object.set_resource_type(properties.resource_type)


class VictimAssetFilterObject(FilterObject):
    """ """

    def __init__(self, base_uri, tcl, victim_asset_type_enum=None):
        """ """
        super(VictimAssetFilterObject, self).__init__(base_uri, tcl)
        self._owners = []

        # get resource type from indicator type
        if isinstance(victim_asset_type_enum, VictimAssetType):
            # get resource type from indicator type number
            resource_type = ResourceType(victim_asset_type_enum.value)

            # get resource properties from resource type name
            self._properties = ResourceProperties[resource_type.name].value(base_uri=self.base_uri)
        else:
            self._properties = ResourceProperties['VICTIM_ASSETS'].value(base_uri=self.base_uri)

        self._resource_type = self._properties.resource_type

        # create default request object for filtered request with only owners
        self._request_object = RequestObject('victimAssets', 'default')
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
