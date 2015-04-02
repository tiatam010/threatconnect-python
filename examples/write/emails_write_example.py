""" standard """
import sys

""" custom """
from examples.working_init import *

enable_add = True
enable_upd = True
enable_del = True


def main():
    """ """
    resources = tc.emails()
    resource_id = None

    if enable_add:
        """ """
        resource = resources.add_resource('bcs bad email')
        resource.set_body('This is a test email body.')
        resource.set_from('bcs_bad_guy@badguysareus.com')
        resource.set_header('This is a test email header.')
        resource.set_subject('This is a test email subject.')
        resource.set_to('victim@goodguys.com')
        resources.send()

        for res in resources:
            print(res)
            resource_id = res.get_id()

    if enable_upd:
        """ """
        resource = resources.update(resource_id)
        resource.set_name('bcs bad email')
        resource.set_body('This is an updated email body.')
        resource.set_header('This is an updated email header.')
        resource.set_subject('This is an updated email subject.')
        # resource.set_to('victim@goodguys.com')
        resources.send()

    if enable_del:
        resources.delete(resource_id)

if __name__ == "__main__":
    main()
