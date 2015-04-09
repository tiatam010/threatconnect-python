""" standard """
from random import randint
import re

""" custom """
from examples.working_init import *


def main():
    """ """
    resources = tc.documents()
    resources.retrieve()

    # random number
    randy = randint(1, 1000)

    for res in resources:
        if res.get_id() == 752435:
            print(res)
            #
            # update resource
            #
            res.set_name('bcs test %s' % randy)
            res.set_file_name('bcs_%s.doc' % randy)

            #
            # attributes
            #
            resources.get_attributes(res)
            for attribute in res.attribute_objects:
                # delete attribute
                if re.findall('test', attribute.get_value()):
                    resources.attribute_delete(res, attribute)
                # update attribute
                if re.findall('update', attribute.get_value()):
                    resources.attribute_update(res, attribute, 'updated attribute %s' % randy)
            # add attribute
            resources.attribute_add(res, 'Description', 'test attribute %s' % randy)

            #
            # tags
            #
            resources.get_tags(res)
            for tag in res.tag_objects:
                # delete tag
                if re.findall('DELETE', tag.get_name()):
                    resources.delete_tag(res, tag.get_name())
            # add tag
            resources.add_tag(res, 'DELETE_%s' % randy)

        #
        # delete resource
        #
        if re.findall('DELETE', res.get_name()):
            res.delete()

    #
    # add resource
    #
    resource = resources.add('DELETE %s' % randy)
    resource.set_file_name('bcs.doc')
    resources.add_tag(resource, 'TAG %s' % randy)

    #
    # update resource
    #
    # resource = resources.update(749422)
    # resource.set_name('Manual Update Adversary Example %s' % randy)

    #
    # delete resource
    #
    # resources.delete(752422)

    resources.commit()

    for res in resources:
        print(res)

    tc.display_report()

if __name__ == "__main__":
    main()
