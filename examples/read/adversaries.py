from examples.working_init import *

""" Working with Adversaries """

""" Toggle the Boolean to enable specific examples """
enable_example1 = False
enable_example2 = False
enable_example3 = True
enable_example4 = False
enable_example5 = False


def show_data(result_obj):
    """  """
    pd('Adversaries', header=True)

    if result_obj.get_status().name == "SUCCESS":
        for obj in result_obj:
            print(obj)
            # tc.get_attributes(obj)
            # for attr_obj in obj.attribute_objects:
            #     print(attr_obj)

            # result_obj.get_tags(obj)
            # for tag_obj in obj.tag_objects:
            #     print(tag_obj)

    #
    # print any error messages
    #
    print("Errors:")
    for err in result_obj.get_errors():
        print(err)

    #
    # print report
    #
    print(tc.report)


def main():
    """ """
    # set threat connect log (tcl) level
    tc.set_tcl_filename('tc.log')
    tc.set_tcl_level('debug')
    tc.set_tcl_console_level('debug')

    # owners = ['Test & Org']
    owners = ['sumx.us']

    if enable_example1:
        """ get adversaries for owner org """

        # optionally set max results
        tc.set_max_results(500)

        # adversary object
        adversaries = Adversaries(tc).retrieve()

        # show indicator data
        show_data(adversaries)

    if enable_example2:
        """ get adversaries for filtered owners """

        # optionally set max results
        tc.set_max_results(500)

        # adversary object
        adversaries = tc.adversaries()

        # get filter
        filter1 = adversaries.add_filter()
        filter1.add_owner(owners)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        adversaries.retrieve()

        # show indicator data
        show_data(adversaries)

    if enable_example3:
        """ get adversaries by id """
        # optionally set max results
        tc.set_max_results(500)
        tc.set_api_sleep(1)

        # adversary object
        adversaries = tc.adversaries()

        # get filter
        filter1 = adversaries.add_filter()
        filter1.add_owner(owners)
        # filter1.add_id(747266)
        filter1.add_tag('Jupyter')
        filter1.add_threat_id(747243)
        filter1.add_pf_name('Manual Update Adversary Sample 957')

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        adversaries.retrieve()

        # show indicator data
        show_data(adversaries)

    if enable_example4:
        """ get adversaries by indicator/indicator_type """

        # optionally set max results
        tc.set_max_results(500)

        # adversary object
        adversaries = tc.adversaries()

        # get filter
        filter1 = adversaries.add_filter()
        filter1.add_owner(owners)
        filter1.add_incident_id(747246)
        filter1.add_indicator('bcs_bad_guy@badguysareus.com')
        filter1.add_security_label('KINDA SECRET')
        filter1.add_tag('BCS')
        filter1.add_threat_id(747243)
        filter1.add_email_id(747227)
        filter1.add_signature_id(747239)
        filter1.add_victim_id(628)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        adversaries.retrieve()

        # show indicator data
        show_data(adversaries)

    if enable_example5:
        """ get adversaries by multiple filters """

        # optionally set max results
        tc.set_max_results(500)

        # adversary object
        adversaries = tc.adversaries()

        # get filter
        filter1 = adversaries.add_filter()
        filter1.add_owner(owners)
        filter1.add_tag('BCS')

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        filter2 = adversaries.add_filter()
        filter2.add_filter_operator(FilterSetOperator.AND)
        filter2.add_owner(owners)
        filter2.add_indicator('4.3.2.1')

        # check for any error on filter creation
        if filter2.error:
            for error in filter2.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        adversaries.retrieve()

        # show indicator data
        show_data(adversaries)

if __name__ == "__main__":
    main()
