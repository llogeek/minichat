

def ssplit(string, delimiter):
    result_list = []
    if not delimiter:
        raise ValueError("Empty Separator")
    if not string:
        return [string]
    start = 0
    for index, char in enumerate(string):
        if char == delimiter:
            result_list.append(string[start:index])
            start = index + 1
    if start == 0:
        return [string]
    result_list.append(string[start:index + 1])
    return result_list

def pack_data(*args):
    return '\n'.join(args)

def unpack_data(data):
    return ssplit(data, '\n')