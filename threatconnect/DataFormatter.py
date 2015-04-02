import inspect
import os
import re
import sys
import types


def format_header(header):
    """  """
    h_len = int((80 - len(str(header))) / 2)
    l_wrapper = '>' * h_len
    r_wrapper = '<' * h_len

    return "\n%s %s %s\n" % (l_wrapper, header, r_wrapper)


def format_item(key, val):
    """  """
    formatted_item = ''
    if isinstance(val, list):
        first_run = True
        for item in val:
            if first_run:
                formatted_item += '%-25s%-25s\n' % ('%s:' % key, item.encode('utf-8').strip())
            else:
                formatted_item += '%-25s%-25s\n' % ('', item.encode('utf-8').strip())
            first_run = False
    elif isinstance(val, str):
        formatted_item += "%-25s%-25s\n" % ('%s:' % key, val.encode('utf-8').strip())
    else:
        formatted_item += "%-25s%-25s\n" % ('%s:' % key, val)
    return formatted_item


def pd(title='', msg='', header=False, color=False, indent=0):
    # get the calling file, module and line number
    call_file = os.path.basename(inspect.stack()[1][0].f_code.co_filename)
    # call_module = inspect.stack()[1][0].f_globals['__name__'].lstrip('Functions.')
    call_line = inspect.stack()[1][0].f_lineno
    module_data = '(%s:%s)' % (call_file, call_line)

    if header:
        h_len = int((80 - len(str(title))) / 2)
        l_wrapper = '_' * h_len
        r_wrapper = '_' * h_len

        print('\n%s %s %s\n' % (l_wrapper, title, r_wrapper))
    else:
        pd_format_msg(title, msg, module_data, indent)


def pd_format_msg(title, msg, module_data='', indent=0):
    formatted_item = ''
    if isinstance(msg, list):
        first_run = True
        for item in msg:
            if first_run:
                formatted_item += '%-25s%-75s' % ('%s:' % title, item)
            else:
                formatted_item += '%-25s%-75s' % ('', item)
            first_run = False
    elif isinstance(msg, str):
        formatted_item += "%-25s%-75s" % ('%s:' % title, msg)
    else:
        formatted_item += "%-25s%-75s" % ('%s:' % title, msg)
    print(formatted_item)
    # print('\t%s' % module_data)

    # if title is not None:
    #     h_len = int((80 - len(str(title))) / 2)
    #     l_wrapper = '_' * h_len
    #     r_wrapper = '_' * h_len
    #
    #     title = "\n%s %s %s\n" % (l_wrapper, title, r_wrapper)
    #
    # # handle each data type
    # if isinstance(msg, (tuple, list)):
    #     if title is not None:
    #         print(title)
    #     if len(msg) == 0:
    #         print("empty list")
    #     else:
    #         indent += 1
    #         for m in msg:
    #             pd_format_msg(None, m, indent=indent)
    # elif isinstance(msg, dict):
    #     if title is not None:
    #         print(title)
    #     if len(msg) == 0:
    #         print("empty dict")
    #     else:
    #         indent += 1
    #         for key, val in sorted(msg.items()):
    #             pd_format_msg(key, val, indent=indent)
    # elif re.findall('enum', str(type(msg))):
    #     if title is not None:
    #         print(title)
    #     print('enum name: %s' % msg.name)
    #     print('enum value: %s' % msg.value)
    # elif isinstance(msg, (float, int, str, unicode, types.NoneType)):
    #     if title is not None:
    #         print(title)
    #     print('%s' % msg)
    # elif isinstance(msg, type(msg)):
    #     if title is not None:
    #         print(title)
    #     print('class: %s' % type(msg))
    #     print("%-40s%-60s%-25s" % (title, '', module_data))
    #     if hasattr(msg, '__str__'):
    #         print('*********')
    #         print(msg)
    #         print('*********')
    # else:
    #     print('type: %s' % type(msg))
    #     print(msg)
    #     sys.exit()
