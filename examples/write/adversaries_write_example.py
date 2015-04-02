""" standard """
import sys

""" custom """
from examples.working_init import *

enable_add = True
enable_upd = True
enable_del = True


def main():
    """ """
    resources = tc.adversaries()
    resource_id = None

    if enable_add:
        """ """
        resources.add_resource('bcs bad guy')
        resources.send()

        for res in resources:
            print(res)
            resource_id = res.get_id()

    if enable_upd:
        resource = resources.update(resource_id)
        resource.set_name('bcs really bad guy')
        resources.send()

        for res in resources:
            print(res)

    if enable_del:
        resources.delete(resource_id)

if __name__ == "__main__":
    main()
