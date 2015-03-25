""" standard """
import base64
import hashlib
import hmac
import json
import socket
import time
import sys

""" third-party """
from requests import (Request, Session, packages)
# disable ssl warning message
packages.urllib3.disable_warnings()

""" custom """
from threatconnect.ErrorCodes import ErrorCodes
from threatconnect.Resources import Indicators
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceProperties import ResourceProperties
from threatconnect.Config.PropertiesEnums import (ApiStatus, FilterSetOperator)
from threatconnect.Resources.Adversaries import Adversaries
from threatconnect.Resources.Attributes import Attributes
from threatconnect.Resources.Documents import Documents
from threatconnect.Resources.Emails import Emails
from threatconnect.Resources.FileOccurrences import FileOccurrences
from threatconnect.Resources.Groups import Groups
from threatconnect.Resources.Incidents import Incidents
from threatconnect.Resources.Owners import Owners
from threatconnect.Resources.Tags import Tags
from threatconnect.Resources.Threats import Threats
from threatconnect.Resources.SecurityLabels import SecurityLabels
from threatconnect.Resources.Signatures import Signatures
from threatconnect.Resources.Victims import Victims
from threatconnect.Resources.VictimAssets import VictimAssets


class ThreatConnect:
    """ """

    def __init__(self, api_aid, api_sec, api_org, api_url, api_max_results=200):
        """ """
        # credentials
        self._api_aid = api_aid
        self._api_sec = api_sec

        # user defined values
        self._api_org = api_org
        self._api_url = api_url
        self._api_max_results = api_max_results

        # config items
        self.api_request_timeout = 10
        self._verify_ssl = False

        # initialize request session handle
        self._session = Session()

        # get all owner names
        # self._owners = self.get_owners().get_owner_names()

    def _api_build_request(self, resource_obj, body=None):
        """ """
        # pd('api_build_request', header=True)
        obj_list = []

        # get resource object values
        http_method = resource_obj.get_http_method()
        resource_type = resource_obj.resource_type
        # properties = ResourceProperties[resource_type.name].value()
        indicator_type_list = ['INDICATORS', 'ADDRESSES', 'EMAIL_ADDRESSES', 'FILES', 'HOSTS', 'URLS']
        if resource_type.name in indicator_type_list:
            modified_since = resource_obj.get_modified_since()
        else:
            modified_since = None
        request_uri = resource_obj.get_request_uri()

        # DEBUG
        # pd('http_method', http_method)
        # pd('modified_since', modified_since)
        # pd('resource_type', resource_type)
        # pd('request_uri', request_uri)
        # pd('get_owner_allowed', resource_obj.get_owner_allowed())
        # pd('get_resource_pagination', resource_obj.get_resource_pagination())

        # update group object
        resource_obj.set_max_results(self._api_max_results)
        resource_obj.add_uris(request_uri)

        # iterate through all owners and results
        if resource_obj.get_owner_allowed() or resource_obj.get_resource_pagination():
            # DEBUG
            # pd('owner or resource_pagination allowed')
            request_payload = {}

            if modified_since is not None:
                request_payload['modifiedSince'] = modified_since

            if resource_obj.get_owner_allowed():
                owners = list(resource_obj.get_owners())
                if not owners:
                    owners = [self._api_org]
                count = len(owners)
            else:
                count = 1

            for x in xrange(count):
                retrieve_data = True

                # only add owner parameter if owners is allowed
                if resource_obj.get_owner_allowed():
                    owner = owners.pop(0)
                    request_payload['owner'] = owner

                    # DEBUG
                    # pd(' owner', owner)
                    # pd('request_payload', request_payload)

                # only add result parameters if resource_pagination is allowed
                if resource_obj.get_resource_pagination():
                    result_limit = int(self._api_max_results)
                    result_remaining = result_limit
                    result_start = 0

                while retrieve_data:
                    # set retrieve data to False to prevent loop for non paginating request
                    retrieve_data = False

                    # only add result parameters if resource_pagination is allowed
                    if resource_obj.get_resource_pagination():
                        request_payload['resultLimit'] = result_limit
                        request_payload['resultStart'] = result_start

                        # DEBUG
                        # pd('result_limit', result_limit)
                        # pd('result_start', result_start)

                    # api call
                    api_response = self._api_request(
                        request_uri, request_payload=request_payload, http_method=http_method, body=body)
                    api_response.encoding = 'utf-8'
                    api_response_dict = api_response.json()
                    api_response_url = api_response.url
                    resource_obj.current_url = api_response_url

                    # update group object with api response data
                    resource_obj.add_api_response(api_response.content)
                    resource_obj.add_status_code(api_response.status_code)
                    resource_obj.add_status(ApiStatus[api_response_dict['status'].upper()])

                    # DEBUG
                    # pd('api_response_url', api_response_url)
                    # pd(api_response_dict['status'], header=True)

                    if api_response_dict['status'] == 'Success':
                        obj_list.extend(self._api_process_response(resource_obj, api_response_dict))

                        # add resource_pagination if required
                        if resource_obj.get_resource_pagination():
                            # get the number of results returned by the api
                            if result_start == 0:
                                result_remaining = api_response_dict['data']['resultCount']

                            result_remaining -= result_limit

                            if result_remaining > 0:
                                retrieve_data = True

                            # increment the start position
                            result_start += result_limit

                            # DEBUG
                            # pd('result_remaining', result_remaining)
                    else:
                        resource_obj.add_error_message(api_response.content)
        else:
            # api call
            api_response = self._api_request(
                request_uri, request_payload={}, http_method=http_method, body=body)
            api_response.encoding = 'utf-8'

            api_response_dict = api_response.json()
            api_response_url = api_response.url
            resource_obj.current_url = api_response_url

            # DEBUG
            # pd('api_response_url', api_response_url)

            # update group object with api response data
            resource_obj.add_api_response(api_response.content)
            resource_obj.add_status_code(api_response.status_code)
            resource_obj.add_status(ApiStatus[api_response_dict['status'].upper()])

            # process the response data
            if api_response_dict['status'] == 'Success':
                processed_data = self._api_process_response(resource_obj, api_response_dict)

                #
                # special case for signature downloads
                #
                # TODO: there is probably a better way to do this, but for now this is it.
                if (resource_type == ResourceType.SIGNATURE and
                        resource_obj.request_object.download):

                    request_uri += '/download'

                    # api call
                    api_response = self._api_request(
                        request_uri, request_payload={}, http_method=http_method, body=body)

                    if api_response['status'] == 'Success':
                        processed_data[0].set_download(api_response['data']['signatureDownload'])

                obj_list.extend(processed_data)
        return obj_list

    @staticmethod
    def _api_process_response(resource_obj, api_response_dict):
        """ """
        # DEBUG
        # pd('api_process_response', header=True)
        obj_list = []

        # update group object with result data
        current_filter = resource_obj.get_current_filter()

        # user resource type from resource object to get the resource properties
        resource_type = resource_obj.resource_type
        properties = ResourceProperties[resource_type.name].value()
        resource_key = properties.resource_key

        response_data = api_response_dict['data'][resource_key]

        # DEBUG
        # pd('current_filter', current_filter)
        # pd('resource_type', resource_type)
        # pd('resource_key', resource_key)

        if isinstance(response_data, dict):
            response_data = [response_data]

        result_count = len(response_data)
        resource_obj.add_result_count(result_count)

        # DEBUG
        # pd('result_count', result_count)

        # update group object with result data
        for data in response_data:
            data_obj_class = resource_obj.get_object_class()
            data_obj = data_obj_class(properties.data_methods)
            data_methods = data_obj.get_data_methods()

            for attrib, obj_method in data_methods.items():
                # DEBUG
                # pd('attrib', attrib)
                if attrib in data:
                    obj_method(data[attrib])
                    # DEBUG
                    # pd('data', data[attrib])
                # else:
                    # DEBUG
                    # pd('missing data object method', attrib)

            resource_obj.add_resource_obj(data_obj)
            # TODO: does this work with matching ids from different owners???
            if (resource_type == ResourceType.TAGS or
                    resource_type == ResourceType.SECURITY_LABEL or
                    resource_type == ResourceType.SECURITY_LABELS):
                stored_obj = resource_obj.get_resource_by_name(data_obj.get_name())
            else:
                stored_obj = resource_obj.get_resource_by_id(data_obj.get_id())

            stored_obj.add_request_url(resource_obj.current_url)
            if current_filter is not None:
                stored_obj.add_matched_filter(current_filter)
            obj_list.append(stored_obj)

        return obj_list

    def _api_request(self, request_uri, request_payload, http_method='GET', body=None, activity_log='false'):
        """ """
        # DEBUG
        # pd('_api_request', header=True)
        # pd('request_uri', request_uri)
        # pd('request_payload', request_payload)
        # pd('http_method', http_method)

        request_uri = request_uri

        # Decide whether or not to suppress all activity logs
        request_payload.setdefault('createActivityLog', activity_log)

        url = '%s%s' % (self._api_url, request_uri)

        if body is not None:
            body_json = json.dumps(body)
        else:
            body_json = None

        # api request
        api_request = Request(
            http_method, url, params=request_payload)
        request_prepped = api_request.prepare()
        # get path url to add to header (required for hmac)
        path_url = request_prepped.path_url
        # TODO: add content-type to api_request_header method
        api_headers = self._api_request_headers(http_method, path_url)
        if http_method in ['POST', 'PUSH']:
            api_headers['Content-Type'] = 'application/json'
            request_prepped.prepare_body(body_json)
        request_prepped.prepare_headers(api_headers)

        # send api request
        try:
            api_response = self._session.send(
                request_prepped, verify=self._verify_ssl, timeout=self.api_request_timeout)
        except socket.error as e:
            print('Error: %s' % e)
            print('The server appears to be down at the moment. The script cannot continue.')
            sys.exit(1)

        # DEBUG
        # pd('url', api_response.url)
        # pd('path_url', path_url)
        # pd('text', api_response.text)

        # pd('END _api_request', header=True)
        return api_response

    def _api_request_headers(self, http_method, api_uri):
        """ """
        timestamp = int(time.time())
        signature = "%s:%s:%d" % (api_uri, http_method, timestamp)
        hmac_signature = hmac.new(self._api_sec, signature, digestmod=hashlib.sha256).digest()
        authorization = 'TC %s:%s' % (self._api_aid, base64.b64encode(hmac_signature))

        return {'Timestamp': timestamp, 'Authorization': authorization}

    def get_filtered_resource(self, resource_obj, filter_objs):
        """ """
        # DEBUG
        # pd('_get_filterd_resource', header=True)
        data_set = None

        if not filter_objs:
            owners = [self._api_org]
            resource_obj.add_owners(owners)
            data_set = self._api_build_request(resource_obj)
        else:
            first_run = True
            for filter_obj in filter_objs:
                # DEUBG
                # pd('filter_obj', filter_objs)
                if resource_obj.resource_type != ResourceType.OWNERS:
                    resource_obj.add_owners(filter_obj.get_owners())
                set_operator = filter_obj.get_filter_operator()

                obj_list = []
                # iterate through each filter method
                if len(filter_obj) > 0:
                    for request_obj in filter_obj:
                        # DEBUG
                        # pd('request_obj', request_obj)
                        resource_obj.set_current_filter(request_obj.name)
                        resource_obj.set_owner_allowed(request_obj.owner_allowed)
                        resource_obj.set_resource_pagination(request_obj.resource_pagination)
                        resource_obj.set_request_uri(request_obj.request_uri)
                        resource_obj.set_resource_type(request_obj.resource_type)
                        #
                        resource_obj.set_request_object(request_obj)
                        obj_list.extend(self._api_build_request(resource_obj))
                else:
                    resource_obj.set_owner_allowed(filter_obj.get_owner_allowed())
                    resource_obj.set_resource_pagination(filter_obj.get_resource_pagination())
                    resource_obj.set_request_uri(filter_obj.get_request_uri())
                    resource_obj.set_resource_type(filter_obj.resource_type)

                    obj_list.extend(self._api_build_request(resource_obj))

                if first_run:
                    data_set = set(obj_list)
                    first_run = False
                    continue

                if set_operator is FilterSetOperator.AND:
                    data_set = data_set.intersection(obj_list)
                elif set_operator is FilterSetOperator.OR:
                    data_set.update(set(obj_list))

        # add data objects to group object
        for obj in data_set:
            resource_obj.add(obj)

    def adversaries(self):
        """ """
        return Adversaries(self)

    def attributes(self):
        """ """
        return Attributes(self)

    def documents(self):
        """ """
        return Documents(self)

    def emails(self):
        """ """
        return Emails(self)

    def file_occurrences(self):
        """ """
        return FileOccurrences(self)

    def groups(self):
        """ """
        return Groups(self)

    def incidents(self):
        """ """
        return Incidents(self)

    def indicators(self):
        """ """
        return Indicators(self)

    def owners(self):
        """ """
        return Owners(self)

    def security_labels(self):
        """ """
        return SecurityLabels(self)

    def signatures(self):
        """ """
        return Signatures(self)

    def tags(self):
        """ """
        return Tags(self)

    def threats(self):
        """ """
        return Threats(self)

    def victims(self):
        """ """
        return Victims(self)

    def victim_assets(self):
        """ """
        return VictimAssets(self)

    def set_max_results(self, max_results):
        """ """
        # validate the max_results is an integer
        if isinstance(max_results, int):
            print(ErrorCodes.e0100.value)
        else:
            self._api_max_results = max_results
