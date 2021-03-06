from examples.working_init import *

""" Working with Groups """

""" Toggle the Boolean to enable specific examples """
enable_example1 = False
enable_example2 = False
enable_example3 = True
enable_example4 = False
enable_example5 = False


def show_data(result_obj):
    """  """
    pd('Groups', header=True)
    # pd('Status', result_obj.get_status())
    # pd('Status Code', result_obj.get_status_code())
    # pd('URIs', result_obj.get_uris())

    if result_obj.get_status().name == "SUCCESS":
        for obj in result_obj:
            print(obj)
    # pd('Stats', header=True)
    # pd('Result Count (Total)', result_obj.get_result_count())
    # pd('Result Count (Filtered)', len(result_obj))

    print(tc.report)


def main():
    """  """
    # get all owner names
    # owners = tc.owners()
    # owners.retrieve()
    # owners.get_owner_names()
    #owners = ['Test & Org']
    owners = ['Common Community']

    if enable_example1:
        """ get groups for owner org """

        # optionally set max results
        tc.set_max_results(500)

        # group object
        groups = tc.groups()

        # retrieve indicators
        groups.retrieve()

        # show indicator data
        show_data(groups)

    if enable_example2:
        """ get groups for filtered owners """

        # optionally set max results
        tc.set_max_results(500)

        # group object
        groups = tc.groups()

        # get filter
        filter1 = groups.add_filter()
        filter1.add_owner(owners)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        groups.retrieve()

        # show indicator data
        show_data(groups)

    if enable_example3:
        """ get groups by group_id/group_type """

        # optionally set max results
        tc.set_max_results(500)

        # group object
        groups = tc.groups()

        # get filter
        filter1 = groups.add_filter()
        filter1.add_owner(owners)
        # filter1.add_email_id(747227)
        filter1.add_indicator('22.83.01.03')

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        groups.retrieve()

        # show indicator data
        show_data(groups)

    if enable_example4:
        """ get groups by indicator/indicator_type """

        # optionally set max results
        tc.set_max_results(500)

        # group object
        groups = tc.groups()

        # get filter
        filter1 = groups.add_filter()
        filter1.add_owner(owners)
        filter1.add_indicator('bcs_bad_guy@badguysareus.com')

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        groups.retrieve()

        # show indicator data
        show_data(groups)

    if enable_example5:
        """ get groups by group_id/group_type and indicator/indicator_type """

        # optionally set max results
        tc.set_max_results(500)

        # group object
        groups = tc.groups()

        # get filter
        filter1 = groups.add_filter()
        filter1.add_owner(owners)
        filter1.add_tag('BCS')

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        filter2 = groups.add_filter()
        filter2.add_owner(owners)
        filter2.add_indicator('bcs_bad_guy@badguysareus.com')

        # check for any error on filter creation
        if filter2.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        groups.retrieve()

        # show indicator data
        show_data(groups)

if __name__ == "__main__":
    main()
