from working_init import *

""" Working with Attributes """

""" Toggle the Boolean to enable specific examples """
enable_example1 = False
enable_example2 = False
enable_example3 = False
enable_example4 = False


def show_data(result_obj):
    """  """
    pd('Attributes', header=True)
    pd('Status', result_obj.get_status())
    pd('Status Code', result_obj.get_status_code())
    pd('URIs', result_obj.get_uris())

    if result_obj.get_status().name == "SUCCESS":
        for obj in result_obj:
            pd('Attribute Data', header=True)
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
    """  """
    # get all owner names
    owners = tc.owners()
    owners.retrieve()
    owners.get_owner_names()

    if enable_example1:
        """ get attributes for filtered owners """

        # optionally set max results
        tc.set_max_results("500")

        # group object
        attributes = tc.attributes()

        # get filter
        filter1 = attributes.add_filter()
        owners = ['Acme Corp']
        filter1.add_owner(owners)
        filter1.add_indicator('23.27.80.231')

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        attributes.retrieve()

        # show indicator data
        show_data(attributes)

    if enable_example2:
        """ get attributes by group_id/group_type """

        # optionally set max results
        tc.set_max_results("500")

        # group object
        attributes = tc.attributes()

        # get filter
        filter1 = attributes.add_filter()
        owners = ['Acme Corp']
        filter1.add_owner(owners)
        filter1.add_email_id(45621)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        attributes.retrieve()

        # show indicator data
        show_data(attributes)

    if enable_example3:
        """ get attributes by indicator/indicator_type """

        # optionally set max results
        tc.set_max_results("500")

        # group object
        attributes = tc.attributes()

        # get filter
        filter1 = attributes.add_filter()
        owners = ['Acme Corp']
        filter1.add_owner(owners)
        filter1.add_indicator('23.27.80.231')
        filter1.add_indicator('8.3.7.34')

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        attributes.retrieve()

        # show indicator data
        show_data(attributes)

    if enable_example4:
        """ get attributes by group_id/group_type and indicator/indicator_type """

        # optionally set max results
        tc.set_max_results("500")

        # group object
        attributes = tc.attributes()

        # get filter
        filter1 = attributes.add_filter()
        owners = ['Acme Corp']
        filter1.add_owner(owners)
        filter1.add_indicator('23.27.80.231')

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        filter2 = attributes.add_filter()
        owners = ['Acme Corp']
        filter2.add_owner(owners)
        filter2.add_indicator('23.27.80.231')

        # check for any error on filter creation
        if filter2.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        attributes.retrieve()

        # show indicator data
        show_data(attributes)

if __name__ == "__main__":
    main()
