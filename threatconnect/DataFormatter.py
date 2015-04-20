import inspect
import os


def format_header(header, l_char='>', r_char='<'):
    """  """
    h_len = int((80 - len(str(header))) / 2)
    l_wrapper = l_char * h_len
    r_wrapper = r_char * h_len

    return "\n%s %s %s\n" % (l_wrapper, header, r_wrapper)


def format_item(key, val, indent=0):
    """  """
    formatted_item = ''
    formatter = ' ' * indent + '%-' + str(30 - indent) + 's%-25s\n'
    if isinstance(val, list):
        first_run = True
        for item in sorted(val):
            if isinstance(item, (str, unicode, int, bool)):
                if first_run:
                    formatted_item += formatter % ('%s:' % key, item.encode('utf-8'))
                else:
                    formatted_item += formatter % ('', item.encode('utf-8').strip())
            elif isinstance(item, type(item)):
                formatted_item += '%s\n' % str(item)
            else:
                if first_run:
                    formatted_item += formatter % ('%s:' % key, item.encode('utf-8'))
                else:
                    formatted_item += formatter % ('', item.encode('utf-8'))
            first_run = False
    elif isinstance(val, str):
        formatter = ' ' * indent + '%-' + str(30 - indent) + 's%-25s\n'
        formatted_item += formatter % ('%s:' % key, val.encode('utf-8'))
    else:
        formatter = ' ' * indent + '%-' + str(30 - indent) + 's%-25s\n'
        formatted_item += formatter % ('%s:' % key, val)
    return formatted_item.encode('utf-8')


def pd(title='', msg='', header=False):
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
        pd_format_msg(title, msg, module_data)


def pd_format_msg(title, msg, module_data=''):
    formatted_item = ''
    if isinstance(msg, list):
        first_run = True
        for item in msg:
            if first_run:
                formatted_item += '%-25s%-75s\n' % ('%s:' % title, item)
            else:
                formatted_item += '%-25s%-75s\n' % ('', item)
            first_run = False
    elif isinstance(msg, dict):
        formatted_item += '%-25s:\n' % title
        for k, v in msg.items():
            formatted_item += '%-25s%-75s\n' % ('%s:' % k, v)
    elif isinstance(msg, str):
        formatted_item += "%-25s%-75s\n" % ('%s:' % title, msg)
    else:
        formatted_item += "%-25s%-75s\n" % ('%s:' % title, msg)
    print(formatted_item.rstrip('\n'))
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
