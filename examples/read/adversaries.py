from examples.working_init import *

""" Working with Adversaries """

""" Toggle the Boolean to enable specific examples """
enable_example1 = True
enable_example2 = False
enable_example3 = False
enable_example4 = False
enable_example5 = False


def show_data(result_obj):
    """  """
    pd('Adversaries', header=True)
    pd('Status', result_obj.get_status())
    pd('Status Code', result_obj.get_status_code())
    pd('URIs', result_obj.get_uris())

    if result_obj.get_status().name == "SUCCESS":
        for obj in result_obj:
            # tc.get_attributes(obj)
            print(obj)
            result_obj.get_tags(obj)
            for tag_obj in obj.tag_objects:
                print(tag_obj)
    pd('Stats', header=True)
    pd('Result Count (Total)', result_obj.get_result_count())
    pd('Result Count (Filtered)', len(result_obj))

    tc.display_report()


def main():
    """ """
    # get all owner names
    # owners = tc.owners()
    # owners.retrieve()
    # owners.get_owner_names()
    owners = ['Test & Org']

    if enable_example1:
        """ get adversaries for owner org """

        # optionally set max results
        tc.set_max_results("500")

        # adversary object
        adversaries = tc.adversaries()

        # retrieve indicators
        adversaries.retrieve()

        # show indicator data
        show_data(adversaries)

    if enable_example2:
        """ get adversaries for filtered owners """

        # optionally set max results
        tc.set_max_results("500")

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
        tc.set_max_results("500")

        # adversary object
        adversaries = tc.adversaries()

        # get filter
        filter1 = adversaries.add_filter()
        filter1.add_owner(owners)
        filter1.add_id(747266)
        filter1.add_tag('BCS')
        filter1.add_threat_id(747243)

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
        tc.set_max_results("500")

        # adversary object
        adversaries = tc.adversaries()

        # get filter
        filter1 = adversaries.add_filter()
        filter1.add_owner(owners)
        filter1.add_incident_id(708917)
        filter1.add_indicator('bigdocomojp.com')
        filter1.add_security_label('DO NOT SHARE')
        filter1.add_tag('China')
        filter1.add_threat_id(125220)
        filter1.add_email_id(45621)
        filter1.add_signature_id(130269)
        filter1.add_victim_id(374)

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
        tc.set_max_results("500")

        # adversary object
        adversaries = tc.adversaries()

        # get filter
        filter1 = adversaries.add_filter()
        filter1.add_owner(owners)
        filter1.add_tag('Company X')

        filter2 = adversaries.add_filter()
        filter2.add_filter_operator(FilterSetOperator.AND)
        filter2.add_owner(owners)
        filter2.add_indicator('60.1.2.243')

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

        # retrieve indicators
        adversaries.retrieve()

        # show indicator data
        show_data(adversaries)

if __name__ == "__main__":
    main()
