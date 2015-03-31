from working_init import *

""" Working with Victim Assets """

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
            pd('Victim Asset Data', header=True)
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
        """ get victim assets for owner org """

        # optionally set max results
        tc.set_max_results("500")

        # victim assets object
        victim_assets = tc.victim_assets()

        # get filter
        # filter1 = victim_assets.add_filter()

        # group 1
        filter1 = victim_assets.add_filter(VictimAssetType.EMAIL_ADDRESSES)
        # filter1.add_id(490)
        filter1.add_id(490, 695)

        # group 2
        filter2 = victim_assets.add_filter(VictimAssetType.NETWORK_ACCOUNTS)
        filter2.add_filter_operator(FilterSetOperator.OR)
        # filter2.add_id(552)
        filter2.add_id(552, 783)

        # group 3
        filter3 = victim_assets.add_filter(VictimAssetType.PHONES)
        filter3.add_filter_operator(FilterSetOperator.OR)
        # filter3.add_id(490)
        filter3.add_id(490, 787)

        # group 4
        filter4 = victim_assets.add_filter(VictimAssetType.SOCIAL_NETWORKS)
        filter4.add_filter_operator(FilterSetOperator.OR)
        # filter4.add_id(543)
        filter4.add_id(543, 740)

        # group 5
        filter5 = victim_assets.add_filter(VictimAssetType.WEBSITES)
        filter5.add_filter_operator(FilterSetOperator.OR)
        # filter5.add_id(284)
        filter5.add_id(284, 297)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        victim_assets.retrieve()

        # show indicator data
        show_data(victim_assets)

    if enable_example2:
        """ get victim assets for filtered owners """

        # optionally set max results
        tc.set_max_results("500")

        # victim_assets object
        victim_assets = tc.victim_assets()

        # get filter
        filter1 = victim_assets.add_filter()
        owners = ['Acme Corp']
        filter1.add_owner(owners)
        filter1.add_indicator('61.106.26.226')

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        victim_assets.retrieve()

        # show indicator data
        show_data(victim_assets)

    if enable_example3:
        """ get victim assets by id """

        # optionally set max results
        tc.set_max_results("500")

        # victim_assets object
        victim_assets = tc.victim_assets()

        # get filter
        filter1 = victim_assets.add_filter()
        owners = ['Acme Corp']
        filter1.add_owner(owners)
        filter1.add_threat_id(125220)
        filter1.add_incident_id(715962)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        victim_assets.retrieve()

        # show indicator data
        show_data(victim_assets)

    if enable_example4:
        """ get victim assets by indicator/indicator_type """

        # optionally set max results
        tc.set_max_results("500")

        # victim_assets object
        victim_assets = tc.victim_assets()

        # get filter
        filter1 = victim_assets.add_filter()
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
        victim_assets.retrieve()

        # show indicator data
        show_data(victim_assets)

    if enable_example5:
        """ get victim assets by multiple filters """

        # optionally set max results
        tc.set_max_results("500")

        # victim_assets object
        victim_assets = tc.victim_assets()

        # get filter
        filter1 = victim_assets.add_filter()
        owners = ['Acme Corp']
        filter1.add_owner(owners)
        filter1.add_incident_id(715962)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # get filter
        filter2 = victim_assets.add_filter()
        owners = ['Acme Corp']
        filter2.add_owner(owners)
        filter2.add_indicator('61.106.26.226')

        # check for any error on filter creation
        if filter2.error:
            for error in filter2.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        victim_assets.retrieve()

        # show indicator data
        show_data(victim_assets)

if __name__ == "__main__":
    main()
