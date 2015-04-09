from examples.working_init import *

""" Working with Security Labels """

""" Toggle the Boolean to enable specific examples """
enable_example1 = False
enable_example2 = False
enable_example3 = False
enable_example4 = False
enable_example5 = False


def show_data(result_obj):
    """  """
    pd('Security Labels', header=True)
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
    """ """
    # get all owner names
    # owners = tc.owners()
    # owners.retrieve()
    # owners = owners.get_owner_names()
    owners = ['Test & Org']

    if enable_example1:
        """ get security_labels for owner org """

        # optionally set max results
        tc.set_max_results("500")

        # security_labels object
        security_labels = tc.security_labels()

        # retrieve indicators
        security_labels.retrieve()

        # show indicator data
        show_data(security_labels)

    if enable_example2:
        """ get security_labels for filtered owners """

        # optionally set max results
        tc.set_max_results("500")

        # security_labels object
        security_labels = tc.security_labels()

        # get filter
        filter1 = security_labels.add_filter()
        filter1.add_owner(owners)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        security_labels.retrieve()

        # show indicator data
        show_data(security_labels)

    if enable_example3:
        """ get security_labels by id """

        # optionally set max results
        tc.set_max_results("500")

        # security_labels object
        security_labels = tc.security_labels()

        # get filter
        filter1 = security_labels.add_filter()
        filter1.add_owner(owners)
        # filter1.add_name('DO NOT SHARE')
        # filter1.add_threat_id(125220, 'DO NOT SHARE')
        # filter1.add_name('KINDA SECRET')
        filter1.add_threat_id(747243, 'KINDA SECRET')

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        security_labels.retrieve()

        # show indicator data
        show_data(security_labels)

    if enable_example4:
        """ get security_labels by indicator/indicator_type """

        # optionally set max results
        tc.set_max_results("500")

        # security_labels object
        security_labels = tc.security_labels()

        # get filter
        filter1 = security_labels.add_filter()
        filter1.add_owner(owners)
        filter1.add_indicator('4.3.2.1')
        filter1.add_threat_id(747243)
        filter1.add_email_id(747227)
        filter1.add_signature_id(747239)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        security_labels.retrieve()

        # show indicator data
        show_data(security_labels)

    if enable_example5:
        """ get security_labels by multiple filters """

        # optionally set max results
        tc.set_max_results("500")

        # security_labels object
        security_labels = tc.security_labels()

        # get filter
        filter1 = security_labels.add_filter()
        filter1.add_owner(owners)
        filter1.add_threat_id(747243)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # get filter
        filter2 = security_labels.add_filter()
        filter2.add_owner(owners)
        filter2.add_email_id(747227)

        # check for any error on filter creation
        if filter2.error:
            for error in filter2.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        security_labels.retrieve()

        # show indicator data
        show_data(security_labels)

if __name__ == "__main__":
    main()
