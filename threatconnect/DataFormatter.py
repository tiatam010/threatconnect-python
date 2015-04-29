import inspect
import os


def format_header(header, l_char='>', r_char='<'):
    """  """
    h_len = int((80 - len(str(header))) / 2)
    l_wrapper = l_char * h_len
    r_wrapper = r_char * h_len

    return str("\n{0} {1} {2}\n".format(l_wrapper, header, r_wrapper))


def format_item(key, val, indent=0):
    """  """
    formatted_item = ''
    formatter = ' ' * indent + '{0:<' + str(30 - indent) + '}{1:<25}\n'
    if isinstance(val, list):
        first_run = True
        for item in sorted(val):
            if isinstance(item, (str, unicode, int, bool)):
                if first_run:
                    formatted_item += formatter.format(key, item)
                else:
                    formatted_item += formatter.format('', item)
            elif isinstance(item, type(item)):
                formatted_item += '{0}\n'.format(str(item))
            else:
                if first_run:
                    formatted_item += formatter.format(key, item)
                else:
                    formatted_item += formatter.format('', item)
            first_run = False
    elif isinstance(val, str):
        formatter = ' ' * indent + '{0:<' + str(30 - indent) + '}{1:<25}\n'
        formatted_item += formatter.format(key, str(val))
    else:
        formatter = ' ' * indent + '{0:<' + str(30 - indent) + '}{1:<25}\n'
        formatted_item += formatter.format(key, str(val))
    return formatted_item


def pd(title='', msg='', header=False):
    # get the calling file, module and line number
    call_file = os.path.basename(inspect.stack()[1][0].f_code.co_filename)
    # call_module = inspect.stack()[1][0].f_globals['__name__'].lstrip('Functions.')
    call_line = inspect.stack()[1][0].f_lineno
    module_data = '({0}:{1})'.format(call_file, call_line)

    if header:
        h_len = int((80 - len(str(title))) / 2)
        l_wrapper = '_' * h_len
        r_wrapper = '_' * h_len

        print('\n{0} {1} {2}\n'.format(l_wrapper, title, r_wrapper))
    else:
        pd_format_msg(title, msg, module_data)


def pd_format_msg(title, msg, module_data=''):
    formatted_item = ''
    if isinstance(msg, list):
        first_run = True
        for item in msg:
            if first_run:
                formatted_item += '{0:<25}{1:<75}\n'.format(title, item)
            else:
                formatted_item += '{0:<25}{1:<75}\n'.format('', item)
            first_run = False
    elif isinstance(msg, dict):
        formatted_item += '{0:<25s}:\n'.format(title)
        for k, v in msg.viewitems():
            formatted_item += '{0:<25}{1:<75}\n'.format(k, v)
    elif isinstance(msg, str):
        formatted_item += '{0:<25}{1:<75}\n'.format(title, msg)
    else:
        formatted_item += '{0:<25}{1:<75}\n'.format(title, msg)
    print(formatted_item.rstrip('\n'))
