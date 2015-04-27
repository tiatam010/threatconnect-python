""" standard """
from random import randint
import re

""" custom """
from examples.working_init import *


def main():
    """ """

    # This is a random number generator used for testing.
    randy = randint(1, 1000)

    # (Required) Instantiate a Resource Object
    resources = tc.emails()

    # (Optional) Filters can be added here if required to narrow the result set.
    # filter1 = resources.add_filter()

    # (Optional) retrieve all results
    resources.retrieve()

    # (Optional) iterate through all results if retrieve was used above
    for res in resources:

        # (Optional) match a particular resource by ID, Name or any other supported attribute.
        # if res.get_id() == 747227:
        if res.get_id() == 44729:
            #
            # update resource if required
            #
            res.set_name('Loop Update Email Sample %s' % randy)
            res.set_body('This is an email body %s.' % randy)
            res.set_header('This is an email header %s.' % randy)
            res.set_subject('This is an email subject %s.' % randy)
            res.set_from('adversary_%s@badguys.com' % randy)
            res.set_to('victim_%s@goodguys.com' % randy)

            #
            # working with indicator associations
            #

            # (Optional) get all indicator associations
            # resources.get_indicator_associations(res)
            resources.get_indicator_associations(res, IndicatorType.EMAIL_ADDRESSES)
            for association in res.association_objects_indicators:
                # add delete flag to all indicator association that have a confidence under 10
                if association.get_confidence() < 10:
                    res.disassociate(association.resource_type, association.get_indicator())

            res.associate(ResourceType.EMAIL_ADDRESSES, 'bcs_bad_guy@badguysareus.com')

            #
            # working with group associations
            #

            # (Optional) get all group associations
            resources.get_group_associations(res)
            for association in res.association_objects_groups:
                # add delete flag to all group association that match DELETE
                if re.findall('Loop', association.get_name()):
                    res.disassociate(association.resource_type, association.get_id())

            # res.associate(ResourceType.ADVERSARIES, 747266)
            res.associate(ResourceType.ADVERSARIES, 3)

            #
            # working with victim associations
            #

            # (Optional) get all victim associations
            resources.get_victim_associations(res)
            for association in res.association_objects_victims:
                # add delete flag to all group association that match DELETE
                if re.findall('BCS', association.get_name()):
                    res.disassociate(association.resource_type, association.get_id())

            res.associate(ResourceType.VICTIMS, 628)

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
            res.add_tag('DELETE_%s' % randy)

        #
        # delete resource if required
        #

        # (Optional) add delete flag to any resource that has 'DELETE' in the name.
        if re.findall('DELETE', res.get_name()):
            res.delete()

    #
    # add resource if required
    #

    # this requires that the resource was instantiated at the beginning of the script.
    resource = resources.add('DELETE %s' % randy)
    # (Required) all required attributes must be provided.
    resource.set_body('This is an email body %s.' % randy)
    resource.set_from('bcs%s@badguys.com' % randy)
    resource.set_header('This is an email header %s.' % randy)
    resource.set_subject('This is an email subject %s.' % randy)
    resource.set_to('victim%s@goodguys.com' % randy)

    # (Optional) add attribute to newly created resource
    resource.add_attribute('Description', 'test attribute %s' % randy)

    # (Optional) add tag to newly created resource
    resource.add_tag('TAG %s' % randy)

    #
    # update resource if required
    #

    # (Optional) a resource can be updated directly by using the resource id.
    resource = resources.update(44728)
    resource.set_name('Manual Update Email Sample %s' % randy)
    resource.set_body('This is an updated email body %s.' % randy)
    resource.set_from('bcs_update%s@badguys.com' % randy)
    resource.set_header('This is an updated email header %s.' % randy)
    resource.set_subject('This is an updated email subject %s.' % randy)
    resource.set_to('victim_update%s@goodguys.com' % randy)

    # (Optional) add attribute to newly created resource
    resource.add_attribute('Description', 'test attribute %s' % randy)

    # (Optional) add tag to newly created resource
    resource.add_tag('TAG %s' % randy)

    #
    # delete resource
    #

    # (Optional) a resource can be deleted directly by using the resource id.
    # resources.delete(752422)

    # (Required) commit all changes above.  No changes are made until the commit phase.
    resources.commit()

    # (Optional) iterate through the result sets after changes.
    for res in resources:
        print(res)

    # (Optional) display a commit report of all API actions performed
    print(tc.report.stats)
    for fail in tc.report.failures:
        print(fail)

if __name__ == "__main__":
    main()
    sys.exit()
