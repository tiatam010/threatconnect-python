from working_init import *

""" Working with Victims """

""" Toggle the Boolean to enable specific examples """
enable_example1 = False
enable_example2 = False
enable_example3 = False
enable_example4 = False
enable_example5 = False


def show_data(result_obj):
    """  """
    pd('Victims', header=True)
    pd('Status', result_obj.get_status())
    pd('Status Code', result_obj.get_status_code())
    pd('URIs', result_obj.get_uris())

    if result_obj.get_status().name == "SUCCESS":
        for obj in result_obj:
            pd('Victim Data', header=True)
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
        """ get victims for owner org """

        # optionally set max results
        tc.set_max_results("500")

        # victims object
        victims = tc.victims()

        # retrieve indicators
        victims.retrieve()

        # show indicator data
        show_data(victims)

    if enable_example2:
        """ get victims for filtered owners """

        # optionally set max results
        tc.set_max_results("500")

        # victims object
        victims = tc.victims()

        # get filter
        filter1 = victims.add_filter()
        owners = ['Acme Corp']
        filter1.add_owner(owners)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        victims.retrieve()

        # show indicator data
        show_data(victims)

    if enable_example3:
        """ get victims by id """

        # optionally set max results
        tc.set_max_results("500")

        # victims object
        victims = tc.victims()

        # get filter
        filter1 = victims.add_filter()
        owners = ['Acme Corp']
        filter1.add_owner(owners)
        filter1.add_id(490)
        filter1.add_threat_id(125220)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        victims.retrieve()

        # show indicator data
        show_data(victims)

    if enable_example4:
        """ get victims by indicator/indicator_type """

        # optionally set max results
        tc.set_max_results("500")

        # victims object
        victims = tc.victims()

        # get filter
        filter1 = victims.add_filter()
        owners = ['Acme Corp']
        filter1.add_owner(owners)
        filter1.add_incident_id(708917)
        filter1.add_indicator('E2C32ED6B9CD40CB87569B769DB669B7')
        filter1.add_indicator('61.106.26.226')
        filter1.add_threat_id(125220)
        filter1.add_email_id(45621)
        filter1.add_signature_id(130269)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        victims.retrieve()

        # show indicator data
        show_data(victims)

    if enable_example5:
        """ get victims by multiple filters """

        # optionally set max results
        tc.set_max_results("500")

        # victims object
        victims = tc.victims()

        # get filter
        filter1 = victims.add_filter()
        owners = ['Acme Corp']
        filter1.add_owner(owners)
        filter1.add_incident_id(715962)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # get filter
        filter2 = victims.add_filter()
        owners = ['Acme Corp']
        filter2.add_owner(owners)
        filter2.add_indicator('61.106.26.226')

        # check for any error on filter creation
        if filter2.error:
            for error in filter2.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        victims.retrieve()

        # show indicator data
        show_data(victims)

if __name__ == "__main__":
    main()
