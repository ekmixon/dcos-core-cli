import sys

from functools import wraps

import docopt

from dcos import cluster, emitting, errors

emitter = emitting.FlatEmitter()


def decorate_docopt_usage(func):
    """Handle DocoptExit exception

    :param func: function
    :type func: function
    :return: wrapped function
    :rtype: function
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
        except docopt.DocoptExit as e:
            emitter.publish("Invalid subcommand usage\n")
            emitter.publish(e)
            return 1
        return result
    return wrapper


def cluster_version_check(func):
    """ Checks that the version of the currently attached cluster is correct
    for this version of the CLI. If not, prints a warning.

    :param func: function
    :type func: function
    :return: wrapped function
    :rtype: function
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        import re

        c = cluster.get_attached_cluster()
        if c is None:
            return func(*args, **kwargs)

        version = c.get_dcos_version()
        m = re.match(r'^(1\.[0-9]+)\D*', version)
        if m is None:
            return func(*args, **kwargs)

        supported_version = "1.14"
        major_version = m.group(1)

        if major_version != supported_version:
            message = ("Warning: The attached cluster is running DC/OS {} "
                       "but this CLI only supports DC/OS {}."
                       ).format(major_version, supported_version)
            emitter.publish(errors.DefaultError(message))

        return func(*args, **kwargs)

    return wrapper


def confirm(prompt, yes):
    """
    :param prompt: message to display to the terminal
    :type prompt: str
    :param yes: whether to assume that the user responded with yes
    :type yes: bool
    :returns: True if the user responded with yes; False otherwise
    :rtype: bool
    """

    if yes:
        return True
    count = 0
    while count < 3:
        sys.stdout.write(f'{prompt} [yes/no] ')
        sys.stdout.flush()
        response = _read_response().lower()
        if response in ['yes', 'y']:
            return True
        elif response in ['no', 'n']:
            return False
        else:
            msg = f"'{response}' is not a valid response."
            emitter.publish(msg)
            count += 1
    return False


def confirm_text(prompt, confirmation_text):
    """
    :param prompt: message to display to the terminal
    :type prompt: str
    :param expected_text: The text to compare user input to.
    :type expected_text: str
    :returns: True if the user replies with the expected text; False otherwise
    :rtype: bool
    """

    for _ in range(3):
        sys.stdout.write(f'{prompt}: ')
        sys.stdout.flush()
        response = _read_response()
        if response == confirmation_text:
            return True
        msg = f"Expected '{confirmation_text}'. You supplied '{response}'."
        emitter.publish(msg)
    return False


def prompt_with_choices(choices, descriptions=[], msg='Please choose:'):
    """
    Allow to pick an item from a list of choices. For example :

        Please choose a login provider for your linked cluster:
        1) dcos-uid-password
        2) saml-sp-initiated
        (1-2): [...]

    :param choices: choices for the list
    :type choices: list of str
    :param descriptions: descriptions for the choices
    :type descriptions: list of str
    :param msg: the message to display before the choices
    :type msg: str
    :returns: the chosen item
    :rtype: str
    """

    if not descriptions:
        descriptions = choices

    if len(choices) != len(descriptions):
        msg = 'Count mismatch between choices and descriptions.'
        raise errors.DCOSException(msg)

    emitter.publish(msg)
    for i, desc in enumerate(descriptions):
        emitter.publish(f'{i + 1}) {desc}')

    # Write to stdout without new line.
    msg = f'(1-{len(choices)}): '
    emitter.publish(msg, end='')

    try:
        chosen_id = int(_read_response())
    except ValueError:
        return None

    return choices[chosen_id-1] if chosen_id <= len(choices) else None


def _read_response():
    """
    :returns: The content of STDIN
    :rtype: str
    """
    return sys.stdin.readline().strip()
