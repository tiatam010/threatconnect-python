
""" custom """
from examples.working_init import *
from threatconnect.Config.VictimAssetType import VictimAssetType

""" Working with Victim Assets """

""" Toggle the Boolean to enable specific examples """
enable_example1 = True
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
            pd(obj)
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
        """ get victim assets for owner org """

        # optionally set max results
        tc.set_max_results("500")

        # victim assets object
        victim_assets = tc.victim_assets()

        # get filter
        filter0 = victim_assets.add_filter()
        filter0.add_id(628)

        # group 1
        filter1 = victim_assets.add_filter(VictimAssetType.EMAIL_ADDRESSES)
        filter1.add_id(564, 840)

        # group 2
        filter2 = victim_assets.add_filter(VictimAssetType.NETWORK_ACCOUNTS)
        filter2.add_filter_operator(FilterSetOperator.OR)
        filter2.add_id(564, 841)

        # group 3
        filter3 = victim_assets.add_filter(VictimAssetType.PHONES)
        filter3.add_filter_operator(FilterSetOperator.OR)
        filter3.add_id(564, 844)

        # group 4
        filter4 = victim_assets.add_filter(VictimAssetType.SOCIAL_NETWORKS)
        filter4.add_filter_operator(FilterSetOperator.OR)
        filter4.add_id(564, 842)

        # group 5
        filter5 = victim_assets.add_filter(VictimAssetType.WEBSITES)
        filter5.add_filter_operator(FilterSetOperator.OR)
        filter5.add_id(564, 843)

        # # check for any error on filter creation
        # if filter1.error:
        #     for error in filter1.get_errors():
        #         pd(error)
        #     sys.exit(1)

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
        filter1.add_owner(owners)
        filter1.add_indicator('4.3.2.1')

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
        filter1.add_owner(owners)
        filter1.add_email_id(747227)
        filter1.add_incident_id(747246)

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
        filter1.add_owner(owners)
        filter1.add_email_id(747227)
        filter1.add_incident_id(747246)
        filter1.add_indicator('4.3.2.1')
        filter1.add_indicator('bcs_bad_guy@badguysareus.com')

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
        filter1.add_owner(owners)
        filter1.add_indicator('bcs_bad_guy@badguysareus.com')

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # get filter
        filter2 = victim_assets.add_filter()
        filter2.add_owner(owners)
        filter2.add_email_id(747227)

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
