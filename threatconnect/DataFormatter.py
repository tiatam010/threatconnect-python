import inspect
import os
import re
import types
# from colored import (fg, attr)


# def split_msg(msg, block_size):
#     msg_list = []
#     n = len(msg)
#     for i in range(0, n, block_size):
#         msg_list.append(msg[i:i+block_size])
#     return msg_list
import sys


def format_header(header):
    """  """
    h_len = int((48 - len(header)) / 2)
    h_wrapper = '=' * h_len

    return "\n%s %s %s\n" % (h_wrapper, header, h_wrapper)


def format_item(key, val):
    """  """
    formatted_item = ""
    if isinstance(val, list):
        first_run = True
        for item in val:
            if first_run:
                formatted_item += "%-25s%-25s\n" % ('%s:' % key, item)
            else:
                formatted_item += "%-25s%-25s\n" % ('', item)
            first_run = False
    else:
        formatted_item += "%-25s%-25s\n" % ('%s:' % key, val)
    return formatted_item


def pd(title='', msg='', header=False, color=False, indent=0):
    # get the calling file, module and line number
    call_file = os.path.basename(inspect.stack()[1][0].f_code.co_filename)
    call_module = inspect.stack()[1][0].f_globals['__name__'].lstrip('Functions.')
    call_line = inspect.stack()[1][0].f_lineno
    border = '=' * int((130 - (len(title)+2))/2)

    # if color:
    #     call_file = '%s%s%s' % (fg('yellow'), call_file, attr('reset'))
    #     call_module = '%s%s%s' % (fg('yellow'), call_module, attr('reset'))
    #     call_line = '%s%s%s' % (fg('yellow'), call_line, attr('reset'))
    #     title = '%s%s%s:%s' % (fg('white'), attr('bold'), title, attr('reset'))
    #     msg = '%s%s%s%s' % (fg('cyan'), attr('bold'), msg, attr('reset'))
    #     border = '%s%s%s' % (fg('green'), border, attr('reset'))

    if header:
        header = '%s %s %s' % (border, title, border)
        print(header)
    else:
        pd_format_msg(title, msg, call_file, call_module, call_line, indent)


def pd_format_msg(
        title, msg, call_file=None, call_module=None, call_line=None, indent=None):
    # msg_type = type(msg)
    # format the output
    if (call_file is None or
            call_module is None or
            call_line is None):
        module_data = ''
    else:
        module_data = '(%s:%s)' % (call_file, call_line)

    if title is not None:
        # format title
        title_border = '-' * int((60 - (len(title)+2))/2)
        title = '%s %s %s' % (title_border, title, title_border)
        title += ' %s' % module_data

    # handle each data type
    if isinstance(msg, (tuple, list)):
        if title is not None:
            print(title)
        if len(msg) == 0:
            print("empty list")
        else:
            indent += 1
            for m in msg:
                pd_format_msg(None, m, indent=indent)
    elif isinstance(msg, dict):
        if title is not None:
            print(title)
        if len(msg) == 0:
            print("empty dict")
        else:
            indent += 1
            for key, val in sorted(msg.items()):
                pd_format_msg(key, val, indent=indent)
    elif re.findall('enum', str(type(msg))):
        if title is not None:
            print(title)
        print('enum name: %s' % msg.name)
        print('enum value: %s' % msg.value)
    elif isinstance(msg, (float, int, str, unicode, types.NoneType)):
        if title is not None:
            print(title)
        print('%s' % msg)
    elif isinstance(msg, type(msg)):
        if title is not None:
            print(title)
        print('class: %s' % type(msg))
        print("%-40s%-60s%-25s" % (title, '', module_data))
        if hasattr(msg, '__str__'):
            print('*********')
            print(msg)
            print('*********')
    else:
        print('type: %s' % type(msg))
        print(msg)
        sys.exit()
