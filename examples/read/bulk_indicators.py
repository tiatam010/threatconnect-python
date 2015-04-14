""" standard """
from datetime import datetime
from threatconnect.Config.FilterOperator import FilterOperator

""" custom """
from examples.working_init import *

""" Working with Indicators """

""" Toggle the Boolean to enable specific examples """
enable_example1 = False
enable_example2 = False
enable_example3 = True


def show_data(result_obj):
    """  """
    pd('Bulk Download', header=True)

    if result_obj.get_status().name == "SUCCESS":
        for obj in result_obj:
            #
            # print object
            #
            print(obj)

            #
            # print attribute
            #
            for attribute_obj in obj.attribute_objects:
                print(attribute_obj)

            #
            # print tags
            #
            for tag_obj in obj.tag_objects:
                print(tag_obj)

    print(tc.report)


def main():
    """ """
    # get all owner names
    # owners_obj = tc.owners()
    # owners_obj.retrieve()
    # all owners
    # owners = owners_obj.get_owner_names()

    owners = ['Test Community']
    # owners = ['Common Community']

    if enable_example1:
        """ get community/source status """

        # optionally set max results
        tc.set_max_results("500")

        # indicator object
        bulk = tc.bulk()
        filter1 = bulk.add_filter()
        filter1.add_owner(owners)

        # retrieve indicators
        bulk.retrieve()

        # show indicator data
        show_data(bulk)

    if enable_example2:
        """ get bulk indicators """

        # optionally set max results
        tc.set_max_results("500")

        # indicator object
        indicators = tc.bulk_indicators()
        filter1 = indicators.add_filter()
        filter1.add_owner(owners)
        filter1.set_format('json')
        filter1.add_confidence(50, FilterOperator.GE)
        filter1.add_date_added('2014-04-10T00:00:00Z', FilterOperator.GE)
        filter1.add_rating('2.0', FilterOperator.GT)
        filter1.add_type('Host')
        filter1.add_last_modified('2015-01-21T00:31:44Z', FilterOperator.LE)
        filter1.add_threat_assess_confidence('95', FilterOperator.GE)
        filter1.add_threat_assess_rating('4.0', FilterOperator.GE)
        filter1.add_tag('China', FilterOperator.EQ)
        filter1.add_attribute('Description', FilterOperator.EQ)

        # retrieve indicators
        indicators.retrieve()

        # show indicator data
        show_data(indicators)

    if enable_example3:
        """ get bulk indicators csv format """

        # the only supported filters on csv format are:
        # confidence
        # rating
        # type

        # optionally set max results
        tc.set_max_results("500")

        # indicator object
        indicators = tc.bulk_indicators()
        filter1 = indicators.add_filter()
        filter1.add_owner(owners)
        filter1.set_format('csv')
        filter1.add_confidence(50, FilterOperator.GE)
        filter1.add_rating('2.0', FilterOperator.GT)
        filter1.add_type('Host')

        # retrieve indicators
        indicators.retrieve()

        # show indicator data
        show_data(indicators)

if __name__ == "__main__":
    main()
