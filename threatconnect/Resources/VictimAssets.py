""" standard """
import types

""" custom """
from threatconnect import FilterMethods, ResourceMethods
from threatconnect.Config.ResourceProperties import ResourceProperties
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.VictimAssetType import VictimAssetType
from threatconnect.Properties.VictimAssetsProperties import VictimAssetsProperties
from threatconnect.Resource import Resource, ResourceObject
from threatconnect.FilterObject import FilterObject

""" Note: PEP 8 intentionally ignored for variable/methods to match API standard. """


class VictimAssets(Resource):
    """ """

    def __init__(self, tc_obj):
        """ """
        super(VictimAssets, self).__init__(tc_obj)
        self._filter_class = VictimAssetFilterObject
        self._object_class = VictimAssetObject

        # set properties
        properties = VictimAssetsProperties()
        self._http_method = properties.http_method
        self._owner_allowed = properties.base_owner_allowed
        self._resource_pagination = properties.resource_pagination
        self._request_uri = properties.base_path
        self._resource_type = properties.resource_type


class VictimAssetObject(ResourceObject):
    """ """

    def __init__(self, data_methods):
        """ """
        super(VictimAssetObject, self).__init__()

        #
        # build data to method mapping
        #
        self._data_methods = {}
        for data_name, methods in data_methods.items():
            # create variables for object
            attribute = methods['var']
            if attribute is not None:
                setattr(self, attribute, None)

            # create add methods for object
            method_name = methods['set']
            method = getattr(ResourceMethods, method_name)
            setattr(self, method_name, types.MethodType(method, self))

            # build api data name to method mapping
            if method_name not in self._data_methods:
                self._data_methods[data_name] = getattr(self, method_name)

            # create add methods for object
            method_name = methods['get']
            if method_name is not None:
                method = getattr(ResourceMethods, method_name)
                setattr(self, method_name, types.MethodType(method, self))
                self.add_method({
                    'name': attribute,
                    'method_name': method_name})


class VictimAssetFilterObject(FilterObject):
    """ """

    def __init__(self, victim_asset_type_enum=None):
        """ """
        super(VictimAssetFilterObject, self).__init__()
        self._owners = []

        # get resource type from indicator type
        if isinstance(victim_asset_type_enum, VictimAssetType):
            # get resource type from indicator type number
            resource_type = ResourceType(victim_asset_type_enum.value)

            # get resource properties from resource type name
            self._properties = ResourceProperties[resource_type.name].value()
        else:
            self._properties = ResourceProperties['VICTIM_ASSETS'].value()

        # define properties for resource type
        self._owner_allowed = self._properties.base_owner_allowed
        self._resource_pagination = self._properties.resource_pagination
        self._request_uri = self._properties.base_path
        self._resource_type = self._properties.resource_type

        #
        # add filter methods
        #
        for method_name in self._properties.filters:
            method = getattr(FilterMethods, method_name)
            setattr(self, method_name, types.MethodType(method, self))
