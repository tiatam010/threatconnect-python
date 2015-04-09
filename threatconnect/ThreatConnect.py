""" standard """
import base64
import hashlib
import hmac
import socket
import time
import sys

""" third-party """
from requests import (Request, Session, packages)
# disable ssl warning message
packages.urllib3.disable_warnings()

""" custom """
from threatconnect.ErrorCodes import ErrorCodes
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceProperties import ResourceProperties
from threatconnect.Config.PropertiesEnums import (ApiStatus, FilterSetOperator)
from threatconnect.ReportEntry import ReportEntry
from threatconnect.Resources.Adversaries import Adversaries
from threatconnect.Resources.Attributes import Attributes
from threatconnect.Resources.Documents import Documents
from threatconnect.Resources.Emails import Emails
from threatconnect.Resources.FileOccurrences import FileOccurrences
from threatconnect.Resources.Groups import Groups
from threatconnect.Resources.Incidents import Incidents
from threatconnect.Resources.Indicators import Indicators
from threatconnect.Resources.Owners import Owners
from threatconnect.Resources.Tags import Tags
from threatconnect.Resources.Threats import Threats
from threatconnect.Resources.SecurityLabels import SecurityLabels
from threatconnect.Resources.Signatures import Signatures
from threatconnect.Resources.Victims import Victims
from threatconnect.Resources.VictimAssets import VictimAssets

from threatconnect.DataFormatter import pd


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
        self._report = []
        self._verify_ssl = False

        # initialize request session handle
        self._session = Session()

        # get all owner names
        # self._owners = self.get_owners().get_owner_names()

    # def api_build_request(self, resource_obj, body=None):
    def api_build_request(self, resource_obj, request_object):
        """ """
        # pd('api_build_request', header=True)
        obj_list = []
        owners = [self._api_org]
        count = len(owners)
        request_payload = None
        result_start = 0
        result_remaining = 0

        # get resource object values
        body = request_object.body
        http_method = request_object.http_method
        resource_type = request_object.resource_type

        # special case for modified since
        indicator_type_list = ['INDICATORS', 'ADDRESSES', 'EMAIL_ADDRESSES', 'FILES', 'HOSTS', 'URLS']
        if resource_type.name in indicator_type_list:
            modified_since = request_object.modified_since
        else:
            modified_since = None

        # request uri
        request_uri = request_object.request_uri

        # DEBUG
        # pd('body', body)
        # pd('http_method', http_method)
        # pd('modified_since', modified_since)
        # pd('resource_type', resource_type)
        # pd('request_uri', request_uri)
        # pd('get_owner_allowed', request_object.owner_allowed)
        # pd('get_resource_pagination', request_object.resource_pagination)

        # update resource object with max results
        resource_obj.set_max_results(self._api_max_results)

        # append uri to resource object
        resource_obj.add_uris(request_uri)

        # iterate through all owners and results
        if request_object.owner_allowed or request_object.resource_pagination:
            # DEBUG
            # pd('owner or resource_pagination allowed')
            request_payload = {}

            if modified_since is not None:
                request_payload['modifiedSince'] = modified_since

            if request_object.owner_allowed:
                if len(list(request_object.owners)) > 0:
                    owners = list(request_object.owners)
                count = len(owners)

            for x in xrange(count):
                retrieve_data = True

                # only add_obj owner parameter if owners is allowed
                if request_object.owner_allowed:
                    owner = owners.pop(0)
                    request_payload['owner'] = owner

                    # DEBUG
                    # pd(' owner', owner)
                    # pd('request_payload', request_payload)

                # only add_obj result parameters if resource_pagination is allowed
                if request_object.resource_pagination:
                    result_limit = int(self._api_max_results)
                    result_remaining = result_limit
                    result_start = 0

                while retrieve_data:
                    # set retrieve data to False to prevent loop for non paginating request
                    retrieve_data = False

                    # only add_obj result parameters if resource_pagination is allowed
                    if request_object.resource_pagination:
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

                    if api_response_dict['status'] == 'Success' and 'data' in api_response_dict:
                        obj_list.extend(self._api_process_response(
                            resource_obj, api_response, request_object))

                        # add_obj resource_pagination if required
                        if request_object.resource_pagination:
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
            if (api_response_dict['status'] == 'Success' and
                    http_method != 'DELETE' and
                    'data' in api_response_dict):
                processed_data = self._api_process_response(
                    resource_obj, api_response, request_object)

                #
                # special case for signature downloads
                #
                # TODO: there is probably a better way to do this, but for now this is it.
                if (resource_type == ResourceType.SIGNATURE and
                        http_method == 'GET' and request_object.download):

                    request_uri += '/download'

                    # api call
                    api_response = self._api_request(
                        request_uri, request_payload={}, http_method=http_method, body=body)

                    if api_response.status_code == 200:
                        # processed_data[0].set_download(api_response['data']['signatureDownload'])
                        processed_data[0].set_download(api_response.content)

                obj_list.extend(processed_data)

        #
        # add report entry
        #
        report_entry = ReportEntry()
        report_entry.set_action(request_object.description)
        report_entry.set_resource_type(resource_obj.resource_type)
        report_entry.set_status(api_response_dict['status'])
        report_entry.add_data({'Request Name': request_object.name})
        report_entry.add_data({'HTTP Method': http_method})
        report_entry.add_data({'Request URI': request_uri})
        if request_payload:
            report_entry.add_data(request_payload)
        self.add_report_entry(report_entry)

        return obj_list

    @staticmethod
    def _api_process_response(resource_obj, api_response, request_object):
        """ """
        # DEBUG
        # pd('api_process_response', header=True)
        resource_object_id = request_object.resource_object_id
        obj_list = []

        # convert json response to dict
        api_response_dict = api_response.json()
        api_response_url = api_response.url

        # update group object with result data
        current_filter = resource_obj.get_current_filter()

        # use resource type from resource object to get the resource properties
        # resource_type = resource_obj.resource_type
        properties = ResourceProperties[request_object.resource_type.name].value()
        resource_key = properties.resource_key

        response_data = api_response_dict['data'][resource_key]

        # DEBUG
        # pd('current_filter', current_filter)
        # pd('resource_type', resource_type)
        # pd('resource_key', resource_key)

        # wrap single response item in a list
        if isinstance(response_data, dict):
            response_data = [response_data]

        result_count = len(response_data)
        resource_obj.add_result_count(result_count)

        # DEBUG
        # pd('result_count', result_count)

        # update group object with result data
        for data in response_data:
            if resource_object_id is not None:
                data_obj = resource_obj.get_resource_by_identity(resource_object_id)
            else:
                data_obj = properties.resource_object
            data_methods = data_obj.get_data_methods()

            for attrib, obj_method in data_methods.items():
                # DEBUG
                if attrib in data:
                    obj_method(data[attrib])
                    # DEBUG
                    # pd('data', data[attrib])
                    # else:
                    # DEBUG
                    # pd('missing data object method', attrib)

            data_obj.validate()

            # get resource object id of newly created object or of the previously
            # created object

            # TODO: does this work with matching ids from different owners???
            # a better way may be to hash all values if the order in which they are
            # concatenated is always the same.

            # if the object supports id then use the id
            if hasattr(data_obj, 'get_id'):
                index = data_obj.get_id()
            elif hasattr(data_obj, 'get_name'):
                index = data_obj.get_name()
            else:
                # all object should either support get_id or get_name.
                print('This should never happen.')
                sys.exit(1)

            # add the resource to the master resource object list to make intersections
            # and joins simple when processing filters
            roi = resource_obj.add_master_resource_obj(data_obj, index)

            # get stored object by the returned object id
            stored_obj = resource_obj.get_resource_by_identity(roi)

            # update the api response url and current filter
            stored_obj.add_request_url(api_response_url)
            stored_obj.set_request_object(request_object)
            stored_obj.set_stage('new')
            stored_obj.add_matched_filter(current_filter)

            # append the object to obj_list to be returned for further filtering
            obj_list.append(stored_obj)

        return obj_list

    def _api_request(
            self, request_uri, request_payload, http_method='GET', body=None,
            activity_log='false', content_type='application/json'):
        """ """
        # DEBUG
        # pd('_api_request', header=True)
        # pd('request_uri', request_uri)
        # pd('request_payload', request_payload)
        # pd('http_method', http_method)
        # pd('body', body)

        request_uri = request_uri

        # Decide whether or not to suppress all activity logs
        request_payload.setdefault('createActivityLog', activity_log)

        url = '%s%s' % (self._api_url, request_uri)

        # api request
        api_request = Request(
            http_method, url, data=body, params=request_payload)
        request_prepped = api_request.prepare()
        # get path url to add_obj to header (required for hmac)
        path_url = request_prepped.path_url
        # TODO: add_obj content-type to api_request_header method
        api_headers = self._api_request_headers(http_method, path_url)

        # POST -> add resource, tag or attribute
        # PUT -> update resource, tag or attribute
        # Not all POST or PUT request will have a json body.
        if http_method in ['POST', 'PUT'] and body is not None:
            api_headers['Content-Type'] = content_type
            api_headers['Content-Length'] = len(body)
        request_prepped.prepare_headers(api_headers)

        # commit api request
        try:
            api_response = self._session.send(
                request_prepped, verify=self._verify_ssl, timeout=self.api_request_timeout)
        except socket.error as e:
            print('Error: %s' % e)
            print('The server appears to be down at the moment. The script cannot continue.')
            sys.exit(1)

        # DEBUG
        # pd('dir', dir(api_response))
        # pd('url', api_response.url)
        # pd('text', api_response.text)
        # pd('content', api_response.content)
        # pd('status_code', api_response.status_code)

        # pd('path_url', path_url)

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
            data_set = self.api_build_request(resource_obj, resource_obj._request_object)
        else:
            first_run = True
            for filter_obj in filter_objs:
                # DEBUG
                # pd('filter_obj', filter_objs)
                if resource_obj.resource_type != ResourceType.OWNERS:
                    resource_obj.add_owners(filter_obj.get_owners())
                set_operator = filter_obj.get_filter_operator()

                obj_list = []
                # iterate through each filter method
                if len(filter_obj) > 0:
                    # request object are for api filters
                    for request_obj in filter_obj:
                        # DEBUG
                        # pd('request_obj', request_obj)
                        resource_obj.set_current_filter(request_obj.name)
                        resource_obj.set_owner_allowed(request_obj.owner_allowed)
                        resource_obj.set_resource_pagination(request_obj.resource_pagination)
                        resource_obj.set_request_uri(request_obj.request_uri)
                        resource_obj.set_resource_type(request_obj.resource_type)
                        obj_list.extend(self.api_build_request(resource_obj, request_obj))
                else:
                    # resource_obj.set_owner_allowed(filter_obj.get_owner_allowed())
                    # resource_obj.set_resource_pagination(filter_obj.get_resource_pagination())
                    # resource_obj.set_request_uri(filter_obj.get_request_uri())
                    # resource_obj.set_resource_type(filter_obj.resource_type)

                    obj_list.extend(self.api_build_request(resource_obj, filter_obj.request_object))
                    # obj_list.extend(self.api_build_request(resource_obj, resource_obj.request_obj))

                # after all the api filtering is complete run through
                # post filters
                pf_obj_set = set()
                for pf_obj in filter_obj.get_post_filters():
                    filter_method = getattr(resource_obj, pf_obj.method)
                    pf_obj_set.update(filter_method(pf_obj.filter, pf_obj.operator))

                # intersection pf_obj list with obj_list to apply filters
                # to current result set
                if filter_obj.get_post_filters_len() > 0:
                    obj_list = pf_obj_set.intersection(obj_list)

                if first_run:
                    data_set = set(obj_list)
                    first_run = False
                    continue

                if set_operator is FilterSetOperator.AND:
                    data_set = data_set.intersection(obj_list)
                elif set_operator is FilterSetOperator.OR:
                    data_set.update(set(obj_list))

        # add_obj data objects to group object
        for obj in data_set:
            resource_obj.add_obj(obj)

    # def resource_get_attributes(self, resource_obj):
    #     """ """
    #     resource_type = resource_obj.request_object.resource_type
    #
    #     # get properties for the object
    #     if resource_type.value % 10:
    #         resource_type = ResourceType(resource_type.value - 5)
    #     properties = ResourceProperties[resource_type.name].value()
    #
    #     # build request object
    #     request_object = RequestObject(resource_type.name, resource_obj.get_id())
    #     request_object.set_http_method(properties.http_method)
    #     request_object.set_request_uri(properties.attribute_path % resource_obj.get_id())
    #     request_object.set_owner_allowed(False)
    #     request_object.set_resource_pagination(True)
    #     request_object.set_resource_type(ResourceType.ATTRIBUTES)
    #
    #     attributes = self.attributes()
    #     data_set = self.api_build_request(attributes, request_object)
    #
    #     for obj in data_set:
    #         resource_obj.add_attribute_object(obj)

    # def resource_add_attribute(self, resource_obj, r_type, value, displayed=True):
    #     """
    #     POST /v2/groups/incidents/119842/attributes
    #     Host: api.threatconnect.com
    #     Content-Type:  application/json
    #     {
    #         "type" : "Source",
    #         "value" : "Proprietary TC-IRT Reporting",
    #         "displayed" : true
    #     }
    #     """
    #
    #     body_json = json.dumps({
    #         'type': r_type,
    #         'value': value,
    #         'displayed': displayed})
    #
    #     resource_type = resource_obj.request_object.resource_type
    #
    #     # get properties for the object
    #     if resource_type.value % 10:
    #         resource_type = ResourceType(resource_type.value - 5)
    #     properties = ResourceProperties[resource_type.name].value(PropertiesAction.POST)
    #
    #     # build request object
    #     request_object = RequestObject(resource_type.name, resource_obj.get_id())
    #     request_object.set_description(
    #         'Add attribute type (%s) with value of (%s) to %s resource.' % (r_type, value, resource_type.name.lower()))
    #     request_object.set_body(body_json)
    #     request_object.set_http_method(properties.http_method)
    #     request_object.set_request_uri(properties.attribute_add_path % resource_obj.get_id())
    #     request_object.set_owner_allowed(False)
    #     request_object.set_resource_pagination(False)
    #     request_object.set_resource_type(ResourceType.ATTRIBUTES)
    #
    #     resource_obj.add_attribute_request(request_object)
    #
    #     # # get attribute object for returned data
    #     # attributes = self.attributes()
    #     # data_set = self.api_build_request(attributes, request_object)
    #
    #     # # add returned attribute to resource object
    #     # for obj in data_set:
    #     #     resource_obj.add_attribute_object(obj)
    #     #
    #     # # clean up temporary attribute resource object
    #     # del attributes

    # def resource_delete_attribute(self, resource_obj, attribute):
    #     """
    #     DELETE /v2/groups/threats/666/attributes/12345
    #     Host: api.threatconnect.com
    #     """
    #
    #     resource_type = resource_obj.request_object.resource_type
    #
    #     # get properties for the object
    #     if resource_type.value % 10:
    #         resource_type = ResourceType(resource_type.value - 5)
    #     properties = ResourceProperties[resource_type.name].value(PropertiesAction.DELETE)
    #
    #     # build request object
    #     request_object = RequestObject(resource_type.name, resource_obj.get_id())
    #     request_object.set_description(
    #         'Delete attribute id (%s) from resource id (%s).' % (attribute.get_id(), resource_obj.get_id()))
    #     request_object.set_http_method(properties.http_method)
    #     request_object.set_request_uri(
    #         properties.attribute_delete_path % (resource_obj.get_id(), attribute.get_id()))
    #     request_object.set_owner_allowed(False)
    #     request_object.set_resource_pagination(False)
    #     request_object.set_resource_type(ResourceType.ATTRIBUTES)
    #
    #     # add request to resource object to process on commit
    #     resource_obj.add_attribute_request(request_object)

    # def resource_get_tags(self, resource_obj):
    #     """ """
    #     resource_type = resource_obj.request_object.resource_type
    #
    #     # get properties for the object
    #     if resource_type.value % 10:
    #         resource_type = ResourceType(resource_type.value - 5)
    #     properties = ResourceProperties[resource_type.name].value()
    #
    #     # build request object
    #     request_object = RequestObject(resource_type.name, resource_obj.get_id())
    #     request_object.set_http_method(properties.http_method)
    #     request_object.set_request_uri(properties.tag_path % resource_obj.get_id())
    #     request_object.set_owner_allowed(False)
    #     request_object.set_resource_pagination(True)
    #     request_object.set_resource_type(ResourceType.TAGS)
    #
    #     tags = self.tags()
    #     data_set = self.api_build_request(tags, request_object)
    #
    #     for obj in data_set:
    #         resource_obj.add_tag_object(obj)

    # def resource_add_tags(self, resource_obj, tag):
    #     """
    #     DELETE /v2/indicators/emailAddresses/oldhat@irrelevant.net/tags/APT
    #     DELETE /v2/indicators/emailAddresses/oldhat@irrelevant.net/tags/APT
    #     POST /v2/indicators/addresses/192.168.0.1/tags/Tracked
    #     POST /v2/groups/incidents/119842/attributes
    #     Host: api.threatconnect.com
    #     Content-Type:  application/json
    #     {
    #         "type" : "Source",
    #         "value" : "Proprietary TC-IRT Reporting",
    #         "displayed" : true
    #     }
    #     """
    #
    #     resource_type = resource_obj.request_object.resource_type
    #
    #     # get properties for the object
    #     if resource_type.value % 10:
    #         resource_type = ResourceType(resource_type.value - 5)
    #     properties = ResourceProperties[resource_type.name].value(PropertiesAction.POST)
    #
    #     # build request object
    #     http_method = properties.http_method
    #     request_uri = properties.tag_add_path % (resource_obj.get_id(), tag)
    #
    #     api_response = self._api_request(request_uri, {}, http_method)
    #     api_response.encoding = 'utf-8'
    #     api_response_dict = api_response.json()
    #
    #     # TODO: status code of 201 might indicate that the tag alread existed.
    #     if api_response_dict['status'] == 'Success':
    #         print('yay')
    #     else:
    #         print('no')

    # def resource_remove_tags(self, resource_obj, tag):
    #     """ """
    #     resource_type = resource_obj.request_object.resource_type
    #
    #     # get properties for the object
    #     if resource_type.value % 10:
    #         resource_type = ResourceType(resource_type.value - 5)
    #     properties = ResourceProperties[resource_type.name].value(PropertiesAction.DELETE)
    #
    #     # build request object
    #     http_method = properties.http_method
    #     request_uri = properties.tag_add_path % (resource_obj.get_id(), tag)
    #
    #     api_response = self._api_request(request_uri, {}, http_method)
    #     api_response.encoding = 'utf-8'
    #     api_response_dict = api_response.json()
    #
    #     # TODO: status code of 201 might indicate that nothing was deleted.
    #     if api_response_dict['status'] == 'Success':
    #         print('yay')
    #     else:
    #         print('no')

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

    def add_report_entry(self, entry):
        """ """
        self._report.append(entry)

    def display_report(self):
        """ """
        print('ThreatConnect API Report:')
        for entry in self._report:
            print(entry)
        print('%s API calls not including pagination.' % len(self._report))

    def set_max_results(self, max_results):
        """ """
        # validate the max_results is an integer
        if isinstance(max_results, int):
            print(ErrorCodes.e0100.value)
        else:
            self._api_max_results = max_results
