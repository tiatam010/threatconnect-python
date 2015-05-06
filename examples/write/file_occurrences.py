""" standard """

""" custom """
from examples.working_init import *

# TODO: add_obj update functionality
# TODO: add_obj delete functionality


def main():
    """ """
    resources = tc.file_occurrences()
    tc.set_tcl_level('debug')
    tc.set_tcl_console_level('debug')

    """ """
    resource = resources.add('AC11BA81F1DC6D3637589FFA04366599')
    resource.set_file_name('bcs.txt')
    resource.set_path('c:/bcs.txt')
    resource.set_date('2014-11-03T00:00:00-05:00')
    resources.commit()

    for res in resources:
        print(res)

    print(tc.report)

if __name__ == "__main__":
    main()
