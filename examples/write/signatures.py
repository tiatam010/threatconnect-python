""" standard """
from random import randint
import re
import sys

""" custom """
from examples.working_init import *

enable_add = True
enable_upd = True
enable_del = True


def main():
    """ """

    # (Required) Instantiate a Resource Object
    resources = tc.signatures()

    # (Optional) Filters can be added here if required to narrow the result set.
    # filter1 = resources.add_filter()

    # (Optional) retrieve all results
    resources.retrieve()

    # This is a random number generator used for testing.
    randy = randint(1, 1000)

    # (Optional) iterate through all results if retrieve was used above
    for res in resources:

        # (Optional) match a particular resource by ID, Name or any other supported attribute.
        if res.get_id() == 747239:
            #
            # update resource if required
            #
            res.set_name('Loop Update Signature Sample %s' % randy)
            res.set_file_name('update_sample_%s.yara' % randy)
            res.set_file_type('YARA')
            file_text = '"' + str(randy) + ' rule example_sig : example\n{\n'
            file_text += 'meta:\n        description = "This '
            file_text += 'is just an example"\n\n '
            file_text += 'strings:\n        $a = {6A 40 68 00 '
            file_text += '30 00 00 6A 14 8D 91}\n        $b = '
            file_text += '{8D 4D B0 2B C1 83 C0 27 99 6A 4E '
            file_text += '59 F7 F9}\n    condition:\n '
            file_text += '$a or $b or $c\n}"'
            res.set_file_text(file_text)

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

            res.associate(ResourceType.ADVERSARIES, 747266)

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
        # download document
        #

        if res.get_id() == 752666:
            res.download()

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
    resource.set_file_name('sample_sig%s.txt' % randy)
    resource.set_file_type('YARA')
    file_text = '"' + str(randy) + ' rule example_sig : example\n{\n'
    file_text += 'meta:\n        description = "This '
    file_text += 'is just an example"\n\n '
    file_text += 'strings:\n        $a = {6A 40 68 00 '
    file_text += '30 00 00 6A 14 8D 91}\n        $b = '
    file_text += '{8D 4D B0 2B C1 83 C0 27 99 6A 4E '
    file_text += '59 F7 F9}\n    condition:\n '
    file_text += '$a or $b or $c\n}"'
    resource.set_file_text(file_text)
    # (Required) all required attributes must be provided.

    # (Optional) add attribute to newly created resource
    resource.add_attribute('Description', 'test attribute %s' % randy)

    # (Optional) add tag to newly created resource
    resource.add_tag('TAG %s' % randy)

    #
    # update resource if required
    #

    # (Optional) a resource can be updated directly by using the resource id.
    resource = resources.update(752666)
    resource.set_name('Manual Update Signature Sample %s' % randy)
    resource.set_file_name('update_sample_sig%s.txt' % randy)

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
        if res.get_id() == 752666:
            print(res.get_file_name())
            print(res.document)

    # (Optional) display a commit report of all API actions performed
    tc.display_report()

if __name__ == "__main__":
    main()
    sys.exit()
