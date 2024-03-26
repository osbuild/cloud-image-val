def color_print(text):
    print('\033[95m' + text + '\033[0m')


def print_divider(text, upper=True, lower=True, center_text=True, length=75):
    free_spaces = int((length / 2) - (len(text) / 2)) if center_text else 0

    if upper:
        color_print('-' * length)

    color_print(' ' * free_spaces + text)

    if lower:
        color_print('-' * length)


def print_debug(vars):
    vars_string = '\n----------DEBUG----------'
    for key, value in vars.items():
        vars_string += f'\n - {key} = {value}'
    vars_string += '\n----------DEBUG----------'
    return vars_string
