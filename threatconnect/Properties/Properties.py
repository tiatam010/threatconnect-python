from threatconnect.Config.PropertiesAction import PropertiesAction


class Properties(object):
    """ """
    def __init__(self, base_uri='v2', http_method=PropertiesAction.GET):
        """ """
        self._base_owner_allowed = False
        self._base_path = '/' + base_uri + '/'
        self._base_uri = base_uri
        self._filter_methods = []
        self._http_method = http_method
        self._resource_pagination = False
        self._resource_type = None
        self._resource_uri_attribute = None
        self._resource_key = None

    @property
    def filters(self):
        """ """
        return self._filter_methods

    @property
    def http_method(self):
        """Get the http method for the request."""
        return self._http_method.name

    @property
    def resource_key(self):
        """ """
        return self._resource_key

    @property
    def resource_pagination(self):
        """Get boolean value indicating if resource_pagination is required."""
        return self._resource_pagination

    @property
    def resource_type(self):
        """ """
        return self._resource_type

    @property
    def resource_uri_attribute(self):
        """ """
        return self._resource_uri_attribute

    #
    # overloaded methods
    #

    @property
    def base_owner_allowed(self):
        """ """
        return None

    @property
    def base_path(self):
        """ """
        return None

    @property
    def adversary_owner_allowed(self):
        """ """
        return None

    @property
    def adversary_path(self):
        """ """
        return None

    @property
    def email_owner_allowed(self):
        """ """
        return None

    @property
    def email_path(self):
        """ """
        return None

    @property
    def id_owner_allowed(self):
        return None

    @property
    def id_path(self):
        return None

    @property
    def incident_owner_allowed(self):
        return None

    @property
    def incident_path(self):
        return None

    @property
    def indicator_owner_allowed(self):
        return None

    @property
    def indicator_path(self):
        return None

    @property
    def security_label_owner_allowed(self):
        return None

    @property
    def security_label_path(self):
        return None

    @property
    def signature_owner_allowed(self):
        return None

    @property
    def signature_path(self):
        return None

    @property
    def tag_owner_allowed(self):
        return None

    @property
    def tag_path(self):
        return None

    @property
    def threat_owner_allowed(self):
        return None

    @property
    def threat_path(self):
        return None

    @property
    def victim_owner_allowed(self):
        return None

    @property
    def victim_path(self):
        return None
