""" standard """
import sys

""" custom """
from examples.working_init import *

enable_add = True
enable_upd = True
enable_del = True


def main():
    """ """
    resources = tc.signatures()
    resource_id = None

    if enable_add:
        """ """
        resource = resources.add_resource('bcs detection signature')
        resource.set_file_name('bcs_detection.txt')
        resource.set_file_type('YARA')
        file_text = '"rule example_sig : example\n{\n'
        file_text += 'meta:\n        description = "This '
        file_text += 'is just an example"\n\n '
        file_text += 'strings:\n        $a = {6A 40 68 00 '
        file_text += '30 00 00 6A 14 8D 91}\n        $b = '
        file_text += '{8D 4D B0 2B C1 83 C0 27 99 6A 4E '
        file_text += '59 F7 F9}\n    condition:\n '
        file_text += '$a or $b or $c\n}"'
        resource.set_file_text(file_text)
        resources.send()

        for res in resources:
            print(res)
            resource_id = res.get_id()

    if enable_upd:
        """ """
        resource = resources.update(resource_id)
        resource.set_name('bcs detection signature updated')
        resource.set_file_name('bcs_detection_updated.txt')
        resource.set_file_type('YARA')
        file_text = '"rule example_sig_upd : example\n{\n'
        file_text += 'meta:\n        description = "This'
        file_text += 'is just an example"\n\n'
        file_text += 'strings:\n        $a = {6A 40 68 00'
        file_text += '30 00 00 6A 14 8D 91}\n        $b ='
        file_text += '{8D 4D B0 2B C1 83 C0 27 99 6A 4E'
        file_text += '59 F7 F9}\n    condition:\n'
        file_text += '$a or $b or $c\n}"'
        resource.set_file_text(file_text)
        resources.send()

    if enable_del:
        resources.delete(resource_id)

if __name__ == "__main__":
    main()
