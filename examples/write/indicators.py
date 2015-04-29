""" standard """
from random import randint
import re
import sys

""" custom """
from examples.working_init import *

enable_example1 = False


def main():
    """ """

    # This is a random number generator used for testing.
    randy = randint(1, 100)

    # (Required) Instantiate a Resource Object
    resources = tc.indicators()

    # (Optional) Filters can be added here if required to narrow the result set.
    # filter1 = resources.add_filter(IndicatorType.ADDRESSES)
    filter1 = resources.add_filter()
    filter1.add_tag('BCS')

    # (Optional) retrieve all results
    resources.retrieve()

    # (Optional) iterate through all results if retrieve was used above
    for res in resources:

        # (Optional) match a particular resource by ID, Name or any other supported attribute.
        if res.get_id() == 196939:
            #
            # update resource if required
            #
            res.set_confidence(randy)
            res.set_rating(randint(0, 5))

            #
            # working with indicator associations
            #

            # CAN pull indicator to indicator associations,
            # but CANNOT associate indicator with indicator
            # # (Optional) get all indicator associations
            # resources.get_indicator_associations(res)
            # # resources.get_indicator_associations(res, IndicatorType.EMAIL_ADDRESSES)
            # for association in res.association_objects_indicators:
            #     print(association)

            #
            # working with group associations
            #

            # (Optional) get all group associations
            resources.get_group_associations(res)
            for association in res.association_objects_groups:
                # add delete flag to all group association that match DELETE
                if re.findall('Loop', association.get_name()):
                    res.disassociate(association.resource_type, association.get_id())

            res.associate(ResourceType.ADVERSARIES, 747266)

            #
            # working with victim associations
            #

            # CAN pull indicator to victim associations,
            # but CANNOT associate indicator with indicator
            # (Optional) get all victim associations
            # resources.get_victim_associations(res)
            # for association in res.association_objects_victims:
            #     print(association)

            #
            # working with attributes
            #
            # (Optional) get all attributes associated with this resource
            resources.get_attributes(res)
            for attribute in res.attribute_objects:
                # add delete flag to all attributes that have 'test' in the value.
                if re.findall('test', attribute.get_value()):
                    res.delete_attribute(attribute.get_id())
                # add update flag to all attributes that have 'update' in the value.
                if re.findall('update', attribute.get_value()):
                    res.update_attribute(attribute.get_id(), 'updated attribute %s' % randy)
            # (Optional) add attribute to resource with type and value
            res.add_attribute('Description', 'test attribute %s' % randy)

            #
            # working with tags
            #

            # (Optional) get all tags associated with this resource
            resources.get_tags(res)
            for tag in res.tag_objects:
                # add delete flag to all tags that have 'DELETE' in the name.
                if re.findall('DELETE', tag.get_name()):
                    res.delete_tag(tag.get_name())
            # (Optional) add tag to resource
            res.add_tag('DELETE %s' % randy)

        #
        # delete resource
        #

        # (Optional) add delete flag to any resource that start with '4.3.254'.
        if re.findall('4.3.254', res.get_indicator()):
            res.delete()

    #
    # add resource if required
    #

    # this requires that the resource was instantiated at the beginning of the script.
    # resource = resources.add('4.3.254.%s' % randint(0, 254))
    resource = resources.add('ac11ba81f1dc6d3637589ffa04366599')
    resource.set_sha1('bec530f8e0104d4521958309eb9852e073150ac1')
    resource.set_sha256('22010a665da94445f5b505c828d532886541900373d29042cc46c3300a186e28')
    resource.set_confidence(randy)
    resource.set_rating('2.0')

    # (Optional) add attribute to newly created resource
    resource.add_attribute('Description', 'test attribute %s' % randy)

    # (Optional) add tag to newly created resource
    resource.add_tag('TAG %s' % randy)

    # this tag is required for testing
    resource.add_tag('BCS')

    # (Required) commit all changes above.  No changes are made until the commit phase.
    resources.commit()

    # (Optional) iterate through the result sets after changes.
    for res in resources:
        print(res)

    # (Optional) display a commit report of all API actions performed
    print(tc.report.stats)
    for rpt in tc.report:
        print(rpt)

if __name__ == "__main__":
    main()
    sys.exit()
