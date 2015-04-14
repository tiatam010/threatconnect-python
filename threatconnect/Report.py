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

        # attributes
        self._api_calls = 0
        self._results_filtered = 0
        self._results_unfiltered = 0
        self._start = datetime.now()

    def add(self, data_obj):
        """ """
        self._report_objects.append(data_obj)

        # create indexes
        self._status_idx.setdefault(data_obj.status, []).append(data_obj)

    def add_api_call(self):
        """ """
        self._api_calls += 1

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
        report += format_item('Run Time', self.runtime)

        return report
