from examples.working_init import *

""" Working with Emails """

""" Toggle the Boolean to enable specific examples """
enable_example1 = False
enable_example2 = False
enable_example3 = False
enable_example4 = False
enable_example5 = False


def show_data(result_obj):
    """  """
    pd('Emails', header=True)
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
    """ """
    # get all owner names
    # owners = tc.owners()
    # owners.retrieve()
    # owners.get_owner_names()
    owners = ['Test & Org']

    if enable_example1:
        """ get emails for owner org """

        # optionally set max results
        tc.set_max_results(500)

        # email object
        email = tc.emails()

        # retrieve indicators
        email.retrieve()

        # show indicator data
        show_data(email)

    if enable_example2:
        """ get emails for filtered owners """

        # optionally set max results
        tc.set_max_results(500)

        # email object
        email = tc.emails()

        # get filter
        filter1 = email.add_filter()
        filter1.add_owner(owners)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        email.retrieve()

        # show indicator data
        show_data(email)

    if enable_example3:
        """ get emails by id """

        # optionally set max results
        tc.set_max_results(500)

        # email object
        email = tc.emails()

        # get filter
        filter1 = email.add_filter()
        filter1.add_owner(owners)
        filter1.add_id(747227)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        email.retrieve()

        # show indicator data
        show_data(email)

    if enable_example4:
        """ get emails by indicator/indicator_type """

        # optionally set max results
        tc.set_max_results(500)

        # email object
        email = tc.emails()

        # get filter
        filter1 = email.add_filter()
        filter1.add_owner(owners)
        filter1.add_indicator('bcs_bad_guy@badguysareus.com')
        filter1.add_tag('BCS')
        filter1.add_threat_id(710117)
        filter1.add_adversary_id(747266)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        email.retrieve()

        # show indicator data
        show_data(email)

    if enable_example5:
        """ get emails by multiple filters """

        # optionally set max results
        tc.set_max_results(500)

        # email object
        email = tc.emails()

        # get filter
        filter1 = email.add_filter()
        filter1.add_owner(owners)
        filter1.add_indicator('bcs_bad_guy@badguysareus.com')

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        filter2 = email.add_filter()
        filter2.add_filter_operator(FilterSetOperator.AND)
        filter2.add_owner(owners)
        filter2.add_tag('BCS')

        # check for any error on filter creation
        if filter2.error:
            for error in filter2.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        email.retrieve()

        # show indicator data
        show_data(email)

if __name__ == "__main__":
    main()
