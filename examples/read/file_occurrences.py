from examples.working_init import *

""" Get FileOccurrence """
enable_example1 = False
enable_example2 = False


def show_data(result_obj):
    """  """
    pd('FileOccurrence', header=True)
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
    # owners.get_owner_names()
    owners = ['Test & Org']

    if enable_example1:

        # optionally set max results
        tc.set_max_results("500")

        # file occurrence object
        file_occurrences = tc.file_occurrences()

        # get filter
        filter1 = file_occurrences.add_filter()
        filter1.add_owner(owners)
        filter1.add_hash('AC11BA81F1DC6D3637589FFA04366599')

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        file_occurrences.retrieve()

        # show indicator data
        show_data(file_occurrences)

    if enable_example2:

        # optionally set max results
        tc.set_max_results("500")

        # file occurrence object
        file_occurrences = tc.file_occurrences()

        # get filter
        filter1 = file_occurrences.add_filter()
        filter1.add_owner(owners)
        filter1.add_hash('AC11BA81F1DC6D3637589FFA04366599', '14727')

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        file_occurrences.retrieve()

        # show indicator data
        show_data(file_occurrences)

if __name__ == "__main__":
    main()
