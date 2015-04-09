""" standard """
from random import randint
import re
import sys

""" custom """
from examples.working_init import *

enable_example1 = False


def main():
    """ """
    resources = tc.indicators()
    # filter1 = resources.add_filter(IndicatorType.ADDRESSES)
    filter1 = resources.add_filter()
    filter1.add_tag('BCS')
    resources.retrieve()

    # random number
    randy = randint(1, 100)

    for res in resources:
        if res.get_id() == 1837687:
            #
            # update resource
            #
            res.set_confidence(randy)
            res.set_rating(randint(0, 5))

            #
            # working with indicator associations
            #

            # CAN pull indicator to indicator relationship,
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

            # (Optional) get all victim associations
            resources.get_victim_associations(res)
            for association in res.association_objects_victims:
                print(association)
                # add delete flag to all group association that match DELETE
                # if re.findall('Loop', association.get_name()):
                #     res.disassociate(association.resource_type, association.get_id())

            # res.associate(ResourceType.VICTIMS, 628)

            #
            # attributes
            #
            resources.get_attributes(res)
            for attribute in res.attribute_objects:
                # delete attribute
                if re.findall('test', attribute.get_value()):
                    res.delete_attribute(attribute.get_id())
                # update attribute
                if re.findall('update', attribute.get_value()):
                    res.update_attribute(attribute.get_id(), 'updated attribute %s' % randy)
            # add attribute
            res.add_attribute('Description', 'test attribute %s' % randy)

            #
            # tags
            #
            resources.get_tags(res)
            for tag in res.tag_objects:
                # delete tag
                if re.findall('DELETE', tag.get_name()):
                    res.delete_tag(tag.get_name())
            # add tag
            res.add_tag('DELETE %s' % randy)

        #
        # delete resource
        #
        if re.findall('4.3.254', res.get_indicator()):
            res.delete()

    #
    # add resource
    #
    resource = resources.add('4.3.254.%s' % randint(0, 254))
    resource.add_tag('BCS')  # must be here for filter above
    resource.set_confidence(randy)
    resource.set_rating('2.0')
    resource.add_attribute('Description', 'test attribute %s' % randy)
    resource.add_tag('TAG %s' % randy)

    resources.commit()

    for res in resources:
        print(res)

    tc.display_report()

if __name__ == "__main__":
    main()
    sys.exit()
