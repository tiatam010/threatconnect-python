"""
The Resource data is being pulled from ThreatConnect API so not validation
is being performed.
"""
from threatconnect.Config.ResourceType import ResourceType


def get_body(self):
    """ """
    return self._body


def get_confidence(self):
    """ """
    return self._confidence


def get_date(self):
    """ """
    return self._date


def get_date_added(self):
    """ """
    return self._date_added


def get_description(self):
    """ """
    return self._description


def get_displayed(self):
    """ """
    return self._displayed


def get_dns_active(self):
    """ """
    return self._dns_active


def get_download(self):
    """ """
    return self._download


def get_event_date(self):
    """ """
    return self._event_date


def get_file_name(self):
    """ """
    return self._file_name


def get_file_size(self):
    """ """
    return self._file_size


def get_file_type(self):
    """ """
    return self._file_type


def get_from(self):
    """ """
    return self._from


def get_header(self):
    """ """
    return self._header


def get_id(self):
    """ """
    return self._id


def get_indicator(self):
    """ """
    return self._indicator


def get_last_modified(self):
    """ """
    return self._last_modified


def get_name(self):
    """ """
    return self._name


def get_nationality(self):
    """ """
    return self._nationality


def get_org(self):
    """ """
    return self._org


def get_owner_name(self):
    """ """
    return self._owner_name


def get_path(self):
    """ """
    return self._path


def get_rating(self):
    """ """
    return self._rating


def get_score(self):
    """ """
    return self._score


def get_source(self):
    """ """
    return self._source


def get_subject(self):
    """ """
    return self._subject


def get_suborg(self):
    """ """
    return self._suborg


def get_to(self):
    """ """
    return self._to


def get_type(self):
    """ """
    return self._type


def get_web_link(self):
    """ """
    return self._web_link


def get_whois_active(self):
    """ """
    return self._whois_active


def get_work_location(self):
    """ """
    return self._work_location


def set_address(self, data):
    """ """
    self._indicator = data
    self._type = ResourceType.EMAIL_ADDRESSES


def set_body(self, data):
    """ """
    self._body = data


def set_confidence(self, data):
    """ """
    self._confidence = data


def set_date(self, data):
    """ """
    self._date = data


def set_date_added(self, data):
    """ """
    self._date_added = data


def set_description(self, data):
    """ """
    self._description = data


def set_displayed(self, data):
    """ """
    self._displayed = data


def set_dns_active(self, data):
    """ """
    self._dns_active = data


def set_download(self, data):
    """ """
    self._download = data


def set_event_date(self, data):
    """ """
    self._event_date = data


def set_file_name(self, data):
    """ """
    self._file_name = data


def set_file_size(self, data):
    """ """
    self._file_size = data


def set_file_type(self, data):
    """ """
    self._file_type = data


def set_from(self, data):
    """ """
    self._from = data


def set_hash(self, data):
    """ """
    self._indicator = data
    self._type = ResourceType.FILES


def set_header(self, data):
    """ """
    self._header = data


def set_hostname(self, data):
    """ """
    self._indicator = data
    self._type = ResourceType.HOSTS


def set_id(self, data):
    """ """
    self._id = data


def set_ip(self, data):
    """ """
    self._indicator = data
    self._type = ResourceType.ADDRESSES


def set_indicator(self, data):
    """ """
    self._indicator = data


def set_last_modified(self, data):
    """ """
    self._last_modified = data


def set_name(self, data):
    """ """
    self._name = data


def set_nationality(self, data):
    """ """
    self._nationality = data


def set_org(self, data):
    """ """
    self._org = data


def set_owner(self, data):
    """ """
    self._owner_name = data['name']


def set_owner_name(self, data):
    """ """
    self._owner_name = data


def set_path(self, data):
    """ """
    self._path = data


def set_rating(self, data):
    """ """
    self._rating = data


def set_score(self, data):
    """ """
    self._score = data


def set_source(self, data):
    """ """
    self._source = data


def set_subject(self, data):
    """ """
    self._subject = data


def set_suborg(self, data):
    """ """
    self._suborg = data


def set_text(self, data):
    """ """
    self._indicator = data


def set_to(self, data):
    """ """
    self._to = data


def set_type(self, data):
    """ """
    self._type = data


def set_url(self, data):
    """ """
    self._indicator = data
    self._type = ResourceType.URLS


def set_web_link(self, data):
    """ """
    self._web_link = data


def set_whois_active(self, data):
    """ """
    self._whois_active = data


def set_work_location(self, data):
    """ """
    self._work_location = data
