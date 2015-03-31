""" standard """
import sys

""" custom """
from examples.working_init import *

enable_example1 = True


def main():
    """ """

    if enable_example1:
        """ """
        resources = tc.documents()
        resource = resources.add_resource('bcs bad doc')
        resource.set_file_name('bcs.docx')
        resources.send()

        for res in resources:
            print(res)
            pd('id', res.get_id())

        resources = tc.documents()
        resource = resources.add_resource('bcs bad pdf')
        resource.set_file_name('bcs.pdf')
        resources.send()

        for res in resources:
            print(res)
            pd('id', res.get_id())

if __name__ == "__main__":
    main()
