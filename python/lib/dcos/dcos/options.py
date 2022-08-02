def make_command_summary_string(command_summaries):
    """Construct subcommand summaries

    :param command_summaries: Commands and their summaries
    :type command_summaries: list of (str, str)
    :returns: The subcommand summaries
    :rtype: str
    """

    return ''.join(
        '\n\t{:15}\t{}'.format(command, summary.strip())
        for command, summary in command_summaries
    )


def make_generic_usage_message(doc):
    """Construct generic usage error

    :param doc: Usage documentation for program
    :type doc: str
    :returns: Generic usage error
    :rtype: str
    """

    return f'Unknown option\n{doc}'
