from working_init import *

""" Working with Documents """

""" Toggle the Boolean to enable specific examples """
enable_example1 = False
enable_example2 = False
enable_example3 = False
enable_example4 = False
enable_example5 = False


def show_data(result_obj):
    """  """
    pd('Documents', header=True)
    pd('Status', result_obj.get_status())
    pd('Status Code', result_obj.get_status_code())
    pd('URIs', result_obj.get_uris())

    if result_obj.get_status().name == "SUCCESS":
        for obj in result_obj:
            pd('Document Data', header=True)
            pd('_api_request_url', obj.get_request_url())
            pd('_matched_filters', obj.get_matched_filters())

            # print resource data using dynamic method calls
            for method_data in sorted(obj.get_methods()):
                method = getattr(obj, method_data['method_name'])
                pd(' %s' % method_data['name'], method())
    pd('Stats', header=True)
    pd('Result Count (Total)', result_obj.get_result_count())
    pd('Result Count (Filtered)', len(result_obj))


def main():
    """ """
    # get all owner names
    owners = tc.owners()
    owners.retrieve()
    owners.get_owner_names()

    if enable_example1:
        """ get documents for owner org """

        # optionally set max results
        tc.set_max_results("500")

        # documents object
        documents = tc.documents()

        # retrieve indicators
        documents.retrieve()

        # show indicator data
        show_data(documents)

    if enable_example2:
        """ get documents for filtered owners """

        # optionally set max results
        tc.set_max_results("500")

        # documents object
        documents = tc.documents()

        # get filter
        filter1 = documents.add_filter()
        owners = ['Acme Corp']
        filter1.add_owner(owners)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        documents.retrieve()

        # show indicator data
        show_data(documents)

    if enable_example3:
        """ get documents by id """
        # optionally set max results
        tc.set_max_results("500")

        # documents object
        documents = tc.documents()

        # get filter
        filter1 = documents.add_filter()
        owners = ['Acme Corp']
        filter1.add_owner(owners)
        filter1.add_id(683083)
        # filter1.add_tag('Company X')
        # filter1.add_tag('China')
        # filter1.add_threat_id(125220)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        documents.retrieve()

        # show indicator data
        show_data(documents)

    if enable_example4:
        """ get documents by indicator/indicator_type """

        # optionally set max results
        tc.set_max_results("500")

        # documents object
        documents = tc.documents()

        # get filter
        filter1 = documents.add_filter()
        owners = ['Acme Corp']
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
        documents.retrieve()

        # show indicator data
        show_data(documents)

    if enable_example5:
        """ get documents by multiple filters """

        # optionally set max results
        tc.set_max_results("500")

        # documents object
        documents = tc.documents()

        # get filter
        filter1 = documents.add_filter()
        owners = ['Acme Corp']
        filter1.add_owner(owners)
        filter1.add_tag('Company X')

        filter2 = documents.add_filter()
        filter2.add_filter_operator(FilterSetOperator.AND)
        owners = ['Acme Corp']
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
        documents.retrieve()

        # show indicator data
        show_data(documents)

if __name__ == "__main__":
    main()
