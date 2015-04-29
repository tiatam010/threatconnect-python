""" standard """
from datetime import datetime

""" custom """
from examples.working_init import *
from threatconnect.Config.FilterOperator import FilterOperator

""" Working with Indicators """

""" Toggle the Boolean to enable specific examples """
enable_example1 = False
enable_example2 = False
enable_example3 = False
enable_example4 = False
enable_example5 = True


def show_data(result_obj):
    """  """
    pd('Indicators', header=True)
    pd('Status', result_obj.get_status())
    pd('Status Code', result_obj.get_status_code())
    pd('URIs', result_obj.get_uris())

    if result_obj.get_status().name == "SUCCESS":
        for obj in result_obj:
            print(obj)

    pd('Stats', header=True)
    pd('Result Count (Total)', result_obj.get_result_count())
    pd('Result Count (Filtered)', len(result_obj))

    print(tc.report.stats)
    for fail in tc.report.failures:
        print(fail)


def main():
    """ """
    # get all owner names
    # owners_obj = tc.owners()
    # owners_obj.retrieve()
    # all owners
    # owners = owners_obj.get_owner_names()
    # owners = ['Test & Org']
    # owners = ['Common Community']
    owners = ['braceysummers.com']

    if enable_example1:
        """ get indicators for owner org """

        # optionally set max results
        tc.set_max_results("500")

        # indicator object
        indicators = tc.indicators()

        # retrieve indicators
        indicators.retrieve()

        # show indicator data
        show_data(indicators)

        # get a list of indicators
        # for indicator in indicators.get_indicators():
        #     pd('indicator', indicator)

    if enable_example2:
        """ get indicators for filtered owners """

        # optionally set max results
        tc.set_max_results("500")

        # indicator object
        indicators = tc.indicators()

        # get filter
        filter1 = indicators.add_filter()
        filter1.add_owner(owners)

        # check for any error on filter creation
        if filter1.error:
            for filter_error in filter1.get_errors():
                pd(filter_error)
            sys.exit(1)

        # retrieve indicators
        indicators.retrieve()

        # show indicator data
        show_data(indicators)

    if enable_example3:
        """ get indicators by id """
        # optionally set max results
        tc.set_max_results("500")

        # indicator object
        indicators = tc.indicators()

        # optionally set modified since date
        modified_since = (datetime.isoformat(datetime(2015, 3, 20))) + 'Z'
        indicators.set_modified_since(modified_since)

        # get filter
        # filter1 = indicators.add_filter()
        # filter1 = indicators.add_filter(IndicatorType.ADDRESSES)
        filter1 = indicators.add_filter(IndicatorType.EMAIL_ADDRESSES)
        # filter1 = indicators.add_filter(IndicatorType.FILES)
        # filter1 = indicators.add_filter(IndicatorType.HOSTS)
        # filter1.add_tag('China')
        # filter1 = indicators.add_filter(IndicatorType.URLS)
        filter1.add_owner(owners)
        filter1.add_adversary_id(3)
        # filter1.add_email_id(45621)
        filter1.add_incident_id(708917)
        # filter1.add_incident_id(708996)
        filter1.add_security_label('DO NOT SHARE')
        filter1.add_signature_id(65646)
        filter1.add_tag('China')
        filter1.add_threat_id(146272)
        # filter1.add_victim_id(369)
        # filter1.add_victim_id(386)

        filter1.add_indicator('bigdocomojp.com')
        filter1.add_indicator('23.27.80.231')
        filter1.add_indicator('DCF06BCA3B1B87C8AF3289D0B42D8FE0')
        filter1.add_indicator('kate.lanser@gmail.com')
        filter1.add_indicator('http://demo.host.com')

        filter1.add_pf_date_added('2014-04-10T00:00:00Z', FilterOperator.GE)
        # filter1.add_pf_rating('2.5', FilterOperator.GE)
        # filter1.add_pf_rating(75, FilterOperator.GE)

        # check for any error on filter creation
        if filter1.error:
            for filter_error in filter1.get_errors():
                pd(filter_error)
            sys.exit(1)

        # retrieve indicators
        indicators.retrieve()

        # show indicator data
        show_data(indicators)

    if enable_example4:
        """ get indicators by indicator/indicator_type """

        # optionally set max results
        tc.set_max_results("500")

        # indicator object
        indicators = tc.indicators()

        # get filter
        filter1 = indicators.add_filter(IndicatorType.ADDRESSES)
        filter1.add_owner(owners)
        filter1.add_indicator('dotster.com20@shepherdstown.com')
        filter1.add_tag('backdoor')

        # check for any error on filter creation
        if filter1.error:
            for filter_error in filter1.get_errors():
                pd(filter_error)
            sys.exit(1)

        # retrieve indicators
        indicators.retrieve()

        # show indicator data
        show_data(indicators)

    if enable_example5:
        """ get indicators by multiple filters """

        # optionally set max results
        tc.set_max_results("500")

        # indicator object
        indicators = tc.indicators()

        # get filter
        filter1 = indicators.add_filter()
        filter1.add_owner(owners)
        filter1.add_security_label('APPROVED FOR RELEASE')

        filter2 = indicators.add_filter()
        filter2.add_filter_operator(FilterSetOperator.AND)
        filter2.add_threat_id(146272)

        filter3 = indicators.add_filter()
        # filter3 = indicators.add_filter(IndicatorType.ADDRESSES)
        filter3.add_filter_operator(FilterSetOperator.OR)
        filter3.add_tag('China')

        # check for any error on filter creation
        if filter1.error:
            for filter_error in filter1.get_errors():
                pd(filter_error)
            sys.exit(1)

        # check for any error on filter creation
        if filter2.error:
            for filter_error in filter2.get_errors():
                pd(filter_error)
            sys.exit(1)

        # check for any error on filter creation
        if filter3.error:
            for filter_error in filter3.get_errors():
                pd(filter_error)
            sys.exit(1)

        # retrieve indicators
        indicators.retrieve()

        # show indicator data
        show_data(indicators)

if __name__ == "__main__":
    main()
