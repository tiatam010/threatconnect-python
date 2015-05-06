from examples.working_init import *

""" Working with Signatures """

""" Toggle the Boolean to enable specific examples """
enable_example1 = False
enable_example2 = False
enable_example3 = True
enable_example4 = False
enable_example5 = False


def show_data(result_obj):
    """  """
    pd('Signatures', header=True)
    pd('Status', result_obj.get_status())
    pd('Status Code', result_obj.get_status_code())
    pd('URIs', result_obj.get_uris())

    if result_obj.get_status().name == "SUCCESS":
        for obj in result_obj:
            obj.download()
            print(obj)
    pd('Stats', header=True)
    pd('Result Count (Total)', result_obj.get_result_count())
    pd('Result Count (Filtered)', len(result_obj))


def main():
    """ """
    # get all owner names
    # owners = tc.owners()
    # owners.retrieve()
    # owners.get_owner_names()
    owners = ['Test & Org']

    if enable_example1:
        """ get signatures for owner org """

        # optionally set max results
        tc.set_max_results(500)

        # signatures object
        signatures = tc.signatures()

        # retrieve indicators
        signatures.retrieve()

        # show indicator data
        show_data(signatures)

    if enable_example2:
        """ get signatures for filtered owners """

        # optionally set max results
        tc.set_max_results(500)

        # signatures object
        signatures = tc.signatures()

        # get filter
        filter1 = signatures.add_filter()
        filter1.add_owner(owners)
        filter1.add_date_added('2015-04-02T00:31:44Z', FilterOperator.GE)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        signatures.retrieve()

        # show indicator data
        show_data(signatures)

    if enable_example3:
        """ get signatures by id """

        # optionally set max results
        tc.set_max_results(500)

        # signatures object
        signatures = tc.signatures()

        # get filter
        filter1 = signatures.add_filter()
        filter1.add_owner(owners)
        filter1.add_id(747239)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        signatures.retrieve()

        # show indicator data
        show_data(signatures)

    if enable_example4:
        """ get signatures by indicator/indicator_type """

        # optionally set max results
        tc.set_max_results(500)

        # signatures object
        signatures = tc.signatures()

        # get filter
        filter1 = signatures.add_filter()
        filter1.add_owner(owners)
        filter1.add_indicator('4.3.2.1')
        filter1.add_tag('BCS')

        filter1.add_date_added('2015-04-02T00:31:45Z', FilterOperator.EQ)
        filter1.add_file_type('YARA')

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        signatures.retrieve()

        # show indicator data
        show_data(signatures)

    if enable_example5:
        """ get signatures by multiple filters """

        # optionally set max results
        tc.set_max_results(500)

        # signatures object
        signatures = tc.signatures()

        # get filter
        filter1 = signatures.add_filter()
        filter1.add_owner(owners)
        # filter1.add_tag('BCS')
        filter1.add_date_added('2015-04-02T00:31:43Z', FilterOperator.GE)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # get filter
        filter2 = signatures.add_filter()
        filter2.add_owner(owners)
        filter2.add_indicator('00DF326EEE18617FAE2FDD3684AC1546')
        filter2.add_indicator('4.3.2.1')
        filter2.add_file_type('YARA', FilterOperator.EQ)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        signatures.retrieve()

        # show indicator data
        show_data(signatures)

if __name__ == "__main__":
    main()
