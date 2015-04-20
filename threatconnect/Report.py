""" standard """
from datetime import datetime

""" custom """
from threatconnect.DataFormatter import format_header, format_item


class Report(object):
    """ """
    def __init__(self):
        """ """
        self._report_objects = []

        # indexes
        self._status_idx = {}
        self._status_code_idx = {}

        # attributes
        self._api_calls = 0
        self._request_time = None
        self._results_filtered = 0
        self._results_unfiltered = 0
        self._start = datetime.now()

    def add(self, data_obj):
        """ """
        self._report_objects.append(data_obj)

        # create indexes
        self._status_idx.setdefault(data_obj.status, []).append(data_obj)
        self._status_code_idx.setdefault(data_obj.status_code, []).append(data_obj)

    def add_api_call(self):
        """ """
        self._api_calls += 1

    def add_request_time(self, data):
        """ """
        if self._request_time is None:
            self._request_time = data
        else:
            self._request_time += data

    def add_filtered_results(self, data):
        """ """
        self._results_filtered += data

    def add_unfiltered_results(self, data):
        """ """
        self._results_unfiltered += data

    @property
    def api_calls(self):
        """ """
        return self._api_calls

    @property
    def failures(self):
        """ """
        if 'Failure' in self._status_idx:
            for failed_entry in self._status_idx['Failure']:
                yield '%s' % failed_entry

    @property
    def request_time(self):
        """ """
        return self._request_time

    @property
    def results_filtered(self):
        """ """
        return self._results_filtered

    @property
    def results_unfiltered(self):
        """ """
        return self._results_unfiltered

    @property
    def runtime(self):
        """ """
        return datetime.now() - self._start

    @property
    def stats(self):
        """ """
        report = format_header('Stats', '-', '-')
        report += format_item('API calls', self.api_calls)
        report += format_item('Unfiltered Results', self.results_unfiltered)
        report += format_item('Filtered Results', self.results_filtered)
        # status codes
        for k, v in self._status_code_idx.items():
            report += format_item(k, len(v))
        if self.request_time is not None:
            report += format_item('Request Time', self.request_time)
            report += format_item('Processing Time', (self.runtime - self.request_time))
        report += format_item('Run Time', self.runtime)

        return report.encode('utf-8')

    def __iter__(self):
        """ """
        for ro in self._report_objects:
            """ """
            yield ro

    def __str__(self):
        """ """
        report = format_header('ThreatConnect API Report', '_', '_')
        for entry in self._report_objects:
            report += '%s' % entry
        report += format_header('Stats', '-', '-')
        report += format_item('API calls', self.api_calls)
        report += format_item('Unfiltered Results', self.results_unfiltered)
        report += format_item('Filtered Results', self.results_filtered)
        if self.request_time is not None:
            report += format_item('Request Time', self.request_time)
            report += format_item('Processing Time', (self.runtime - self.request_time))
        report += format_item('Run Time', self.runtime)

        #
        # Failed Request
        #
        # if 'Failure' in self._status_idx:
        #     report += format_header('Failed Request', '!', '!')
        #     for failed_entry in self._status_idx['Failure']:
        #         report += '%s' % failed_entry

        return report.encode('utf-8')
