""" standard """
from random import randint
import re

""" custom """
from examples.working_init import *


def main():
    """ """
    # set threat connect log (tcl) level
    tc.set_tcl_filename('tc.log')
    tc.set_tcl_level('debug')
    tc.set_tcl_console_level('debug')

    # This is a random number generator used for testing.
    randy = randint(1, 1000)

    # (Required) Instantiate a Resource Object
    resources = tc.documents()

    # (Optional) Filters can be added here if required to narrow the result set.
    # filter1 = resources.add_filter()

    # (Optional) retrieve all results
    resources.retrieve()

    # (Optional) iterate through all results if retrieve was used above
    for res in resources:
        print(res)

        # (Optional) match a particular resource by ID, Name or any other supported attribute.
        if res.get_id() == 44813:
            #
            # update resource if required
            #
            res.set_name('Loop Update Document Sample %s' % randy)
            res.set_file_name('bcs_%s.doc' % randy)

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

            res.associate(ResourceType.ADVERSARIES, 3)

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

            # res.associate(ResourceType.VICTIMS, 747266)

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

        if res.get_id() == 752640:
            res.download()

        #
        # delete resource if required
        #

        # (Optional) add delete flag to any resource that has 'DELETE' in the name.
        if re.findall('Delete Document Sample', res.get_name()):
            res.delete()

    #
    # add resource if required
    #

    # this requires that the resource was instantiated at the beginning of the script.
    resource = resources.add('Delete Document Sample %s' % randy)
    # (Required) all required attributes must be provided.
    resource.set_file_name('new_file_%s.txt' % randy)
    data = 'This is a newly created file content {0}.'.format(randy)
    resource.upload(data)

    # (Optional) add attribute to newly created resource
    resource.add_attribute('Description', 'test attribute {0}'.format(randy))

    # (Optional) add tag to newly created resource
    resource.add_tag('TAG {0}'.format(randy))

    #
    # update resource if required
    #

    # (Optional) a resource can be updated directly by using the resource id.
    resource = resources.update(44812)
    resource.set_name('Manual Update Document Sample %s' % randy)
    resource.set_file_name('sample_%s.txt' % randy)
    # data = open('./sample_upload.txt', 'rb').read()
    data = 'This is a file content %s.' % randy
    resource.upload(data, True)

    #
    # delete resource
    #

    # (Optional) a resource can be deleted directly by using the resource id.
    # resources.delete(752422)

    # (Required) commit all changes above.  No changes are made until the commit phase.
    try:
        resources.commit()
    except RuntimeError as e:
        print(e)

    # (Optional) iterate through the result sets after changes.
    for res in resources:
        print(res)
        if res.get_id() == 752640:
            # (Optional) write the document out to a file
            print(res.get_file_name())
            print(res.document)

    # (Optional) display a commit report of all API actions performed
    print(tc.report.stats)

    for fail in tc.report.failures:
        print(fail)

    # for rpt in tc.report:
    #     print(rpt)

if __name__ == "__main__":
    main()
