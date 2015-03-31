""" standard """
import sys

""" custom """
from examples.working_init import *

enable_example1 = True


def main():
    """ """

    if enable_example1:
        """ """
        resources = tc.adversaries()
        resources.add_resource('bcs bad guy')
        resources.send()

        for res in resources:
            print(res)
            pd('id', res.get_id())

        resources = tc.adversaries()
        resources.add_resource('bcs really bad guy')
        resources.send()

        for res in resources:
            print(res)
            pd('id', res.get_id())

if __name__ == "__main__":
    main()
