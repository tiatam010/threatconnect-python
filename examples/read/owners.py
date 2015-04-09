from examples.working_init import *

""" Get Owners """
enable_example1 = False
enable_example2 = False
enable_example3 = False


def show_data(result_obj):
    """  """
    pd('Owners', header=True)
    pd('Status', result_obj.get_status())
    pd('Status Code', result_obj.get_status_code())
    pd('URIs', result_obj.get_uris())

    if result_obj.get_status().name == "SUCCESS":
        for obj in result_obj:
            print(obj)
    pd('Stats', header=True)
    pd('Result Count (Total)', result_obj.get_result_count())
    pd('Result Count (Filtered)', len(result_obj))


def main():
    """
    Method:
    get_owners() ->  This method can be used to get a object containing owners.
    """
    if enable_example1:
        # optionally set the max results the api should return in one request
        tc.set_max_results("500")

        owners = tc.owners()
        owners.retrieve()
        show_data(owners)

    """
    Method:
    get_owners() ->  This method can be used to get a object containing owners filtered by indicator.
    """
    if enable_example2:

        # get owner object
        owners = tc.owners()

        # create a filter
        # If no indicator type is provided the indicator type will be automatically determined.
        filter1 = owners.add_filter()
        filter1.add_indicator('93.54.64.246')
        # filter1.add_indicator('81.206.124.7')
        # filter1.add_indicator('ivyfatima.ferrer@yahoo.com')
        # filter1.add_indicator('E7E20956FEDFD93814505051CA3DB035')
        # filter1.add_indicator('frankhere.oicp.net')
        # filter1.add_indicator('http://eaurougef1.eu/user.php')

        # Optionally provide the indicator type enum.
        # filter1.add_indicator('194.58.101.24', ResourceType.ADDRESSES)
        # filter1.add_indicator('ivyfatima.ferrer@yahoo.com', ResourceType.EMAIL_ADDRESSES)
        # filter1.add_indicator('E7E20956FEDFD93814505051CA3DB035', ResourceType.FILES)
        # filter1.add_indicator('frankhere.oicp.net', ResourceType.HOSTS)
        # filter1.add_indicator('http://eaurougef1.eu/user.php', ResourceType.URLS)

        # FAILURE TESTING
        # filter1.add_indicator('194.58.101.24', ResourceType.FILES)
        # filter1.add_indicator('194.58.101.24', ResourceType.EMAIL_ADDRESSES)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        owners.retrieve()
        show_data(owners)

    """
    Method:
    get_owners() ->  This method can be used to get a object containing owners filtered by indicator.
    """
    if enable_example3:

        # get owner object
        owners = tc.owners()

        # create a filter
        # If no indicator type is provided the indicator type will be automatically determined.
        filter1 = owners.add_filter()
        filter1.add_indicator('93.54.64.246')
        filter1.add_indicator('93.54.64.246')
        filter1.add_indicator('81.206.124.7')
        filter1.add_indicator('ivyfatima.ferrer@yahoo.com')
        # filter1.add_indicator('E7E20956FEDFD93814505051CA3DB035')
        # filter1.add_indicator('frankhere.oicp.net')
        # filter1.add_indicator('http://eaurougef1.eu/user.php')

        filter2 = owners.add_filter()
        filter2.add_filter_operator(FilterSetOperator.AND)
        filter2.add_indicator('E7E20956FEDFD93814505051CA3DB035')
        filter2.add_indicator('frankhere.oicp.net')
        filter2.add_indicator('http://eaurougef1.eu/user.php')

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # check for any error on filter creation
        if filter2.error:
            for error in filter2.get_errors():
                pd(error)
            sys.exit(1)

        owners.retrieve()
        show_data(owners)

if __name__ == "__main__":
    main()
