""" standard """
import sys

""" custom """
from examples.working_init import *

enable_add = True
enable_upd = True
enable_del = True


def main():
    """ """
    resources = tc.incidents()
    resource_id = None

    if enable_add:
        """ """
        resource = resources.add_resource('bcs did it')
        resource.set_event_date('2015-03-26T00:00:00Z ')
        resources.send()

        for res in resources:
            print(res)
            resource_id = res.get_id()

    if enable_upd:
        """ """
        resource = resources.update(resource_id)
        resource.set_name('bcs did it again')
        resource.set_event_date('2015-03-26T12:00:00Z ')
        resources.send()

    if enable_del:
        resources.delete(resource_id)

if __name__ == "__main__":
    main()
