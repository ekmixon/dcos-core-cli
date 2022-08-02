import json
import os
import sys

import docopt
import pkg_resources
import six
from six.moves import urllib

import dcoscli
from dcos import (cmds, config, emitting, http,
                  metronome, options, packagemanager, util)
from dcos.cosmos import get_cosmos_url
from dcos.errors import DCOSException, DCOSHTTPException, DefaultError
from dcoscli import tables
from dcoscli.subcommand import default_command_info, default_doc
from dcoscli.util import cluster_version_check, decorate_docopt_usage


logger = util.get_logger(__name__)
emitter = emitting.FlatEmitter()

DEFAULT_TIMEOUT = 180

# single job, not a lot of data
EMBEDS_FOR_JOB_HISTORY = [
    metronome.EMBED_ACTIVE_RUNS,
    metronome.EMBED_SCHEDULES,
    metronome.EMBED_HISTORY]

# unknown number of jobs, using history summary
EMBEDS_FOR_JOBS_HISTORY = [
    metronome.EMBED_ACTIVE_RUNS,
    metronome.EMBED_SCHEDULES,
    metronome.EMBED_HISTORY_SUMMARY]


def main(argv):
    try:
        return _main(argv)
    except DCOSException as e:
        emitter.publish(e)
        return 1


@decorate_docopt_usage
@cluster_version_check
def _main(argv):

    for i, arg in enumerate(argv):
        if arg == '--show-failures':
            argv[i] = '--failures'
            warning = ("'--show-failures' is deprecated, "
                       "please use '--failures' instead.\n")
            emitter.publish(DefaultError(warning))

    args = docopt.docopt(
        default_doc("job"),
        argv=argv,
        version=f'dcos-job version {dcoscli.version}',
    )


    return cmds.execute(_cmds(), args)


def _check_capability():
    """
    The function checks if cluster has metronome capability.

    :raises: DCOSException if cluster does not have metronome capability
    """

    cosmos = packagemanager.PackageManager(get_cosmos_url())
    if not cosmos.has_capability('METRONOME'):
        raise DCOSException(
            'DC/OS backend does not support metronome capabilities in this '
            'version. Must be DC/OS >= 1.8')


def _cmds():
    """
    :returns: all the supported commands
    :rtype: dcos.cmds.Command
    """

    return [

        cmds.Command(
            hierarchy=['job', 'run'],
            arg_keys=['<job-id>', '--json'],
            function=_run),

        cmds.Command(
            hierarchy=['job', 'kill'],
            arg_keys=['<job-id>', '<run-id>', '--all'],
            function=_kill),

        cmds.Command(
            hierarchy=['job', 'schedule', 'add'],
            arg_keys=['<job-id>', '<schedule-file>'],
            function=_add_schedule),

        cmds.Command(
            hierarchy=['job', 'schedule', 'update'],
            arg_keys=['<job-id>', '<schedule-file>'],
            function=_update_schedules),

        cmds.Command(
            hierarchy=['job', 'schedule', 'show'],
            arg_keys=['<job-id>', '--json'],
            function=_show_schedule),

        cmds.Command(
            hierarchy=['job', 'show', 'runs'],
            arg_keys=['<job-id>', '<run-id>', '--json', '--quiet'],
            function=_show_runs),

        cmds.Command(
            hierarchy=['job', 'schedule', 'remove'],
            arg_keys=['<job-id>', '<schedule-id>'],
            function=_remove_schedule),

        cmds.Command(
            hierarchy=['job', 'list'],
            arg_keys=['--json', '--quiet'],
            function=_list),

        cmds.Command(
            hierarchy=['job', 'queue'],
            arg_keys=['<job-id>', '--json', '--quiet'],
            function=_queue),

        cmds.Command(
            hierarchy=['job', 'history'],
            arg_keys=['<job-id>', '--json', '--failures', '--last', '--quiet'],
            function=_history),

        cmds.Command(
            hierarchy=['job', 'remove'],
            arg_keys=['<job-id>', '--stop-current-job-runs'],
            function=_remove),

        cmds.Command(
            hierarchy=['job', 'add'],
            arg_keys=['<job-file>'],
            function=_add_job),

        cmds.Command(
            hierarchy=['job', 'update'],
            arg_keys=['<job-file>'],
            function=_update_job),

        cmds.Command(
            hierarchy=['job', 'show'],
            arg_keys=['<job-id>'],
            function=_show),

        cmds.Command(
            hierarchy=['job'],
            arg_keys=['--config-schema', '--info'],
            function=_job)
    ]


def _job(config_schema=False, info=False):
    """
    :param config_schema: Whether to output the config schema
    :type config_schema: boolean
    :param info: Whether to output a description of this subcommand
    :type info: boolean
    :returns: process return code
    :rtype: int
    """

    if config_schema:
        schema = _cli_config_schema()
        emitter.publish(schema)
    elif info:
        _info()
    else:
        doc = default_command_info("job")
        raise DCOSException(options.make_generic_usage_message(doc))

    return 0


def _remove_schedule(job_id, schedule_id):
    """
    :param job_id: Id of the job
    :type job_id: str
    :param schedule_id: Id of the schedule
    :type schedule_id: str
    :returns: process return code
    :rtype: int
    """

    try:
        client = metronome.create_client()
        client.remove_schedule(job_id, schedule_id)
    except DCOSHTTPException as e:
        if e.response.status_code == 404:
            raise DCOSException("Schedule or job ID does NOT exist.")
    except DCOSException as e:
        raise DCOSException(
            f"Unable to remove schedule ID '{schedule_id}' for job ID '{job_id}'"
        )


    return 0


def _remove(job_id, stop_current_job_runs=False):
    """
    :param job_id: Id of the job
    :type job_id: str
    :param stop_current_job_runs: If job runs should be stop as
    part of the remove
    :type stop_current_job_runs: boolean
    :returns: process return code
    :rtype: int
    """

    try:
        client = metronome.create_client()
        client.remove_job(job_id, stop_current_job_runs)

    except DCOSHTTPException as e:
        if e.response.status_code == 500 and stop_current_job_runs:
            return _remove(job_id, False)
        else:
            raise DCOSException(f"Unable to remove '{job_id}'.  {e}.")
    except DCOSException as e:
        raise DCOSException(f"Unable to remove '{job_id}'. {e}.")

    return 0


def _queue(job_id, json_flag=False, quiet=False):
    """
    :param job_id: Id of the job
    :type job_id: str
    :param json_flag: Output json if True
    :type json_flag: bool
    :param quiet: Output only job run ids if true
    :type quiet: bool
    :returns: process return code
    :rtype: int
    """

    client = metronome.create_client()
    deployment_list = client.get_queued_job_runs(job_id)

    if not deployment_list and not json_flag:
        if job_id:
            msg = "There are no deployments in the queue for " + f"'{job_id}'"
            emitter.publish(msg)
        return 0

    if quiet:
        for deployment in deployment_list:
            for runs in deployment.get("runs"):
                emitter.publish(runs.get("runId"))
    else:
        emitting.publish_table(emitter,
                               deployment_list,
                               tables.job_queue_table,
                               json_flag)
    return 0


def _kill(job_id, run_id, all=False):
    """
    :param job_id: Id of the job
    :type job_id: str
    :returns: process return code
    :rtype: int
    """
    deadpool = []
    if run_id is None and all is True:
        deadpool = _get_ids(_get_runs(job_id))
    else:
        deadpool.append(run_id)

    client = metronome.create_client()
    for dead in deadpool:
        try:
            client.kill_run(job_id, dead)
        except DCOSHTTPException as e:
            if e.response.status_code == 404:
                raise DCOSException("Job ID or Run ID does NOT exist.")
        except DCOSException as e:
            raise DCOSException(f"Unable stop run ID '{dead}' for job ID '{job_id}'")
        else:
            emitter.publish(f"Run '{dead}' for job '{job_id}' killed.")
    return 0


def _list(json_flag=False, quiet=False):
    """ Provides a list of jobs along with their active runs and history summary
    :returns: process return code
    :rtype: int
    """
    client = metronome.create_client()
    json_list = client.get_jobs(EMBEDS_FOR_JOBS_HISTORY)

    if quiet:
        for job in json_list:
            emitter.publish(job.get('id'))
    elif json_flag:
        emitter.publish(json_list)
    else:
        table = tables.job_table(json_list)
        if output := six.text_type(table):
            emitter.publish(output)

    return 0


def _history(job_id, json_flag=False, failures=False, last=False, quiet=False):
    """
    :returns: process return code
    :rtype: int
    """

    client = metronome.create_client()
    json_history = client.get_job(job_id, EMBEDS_FOR_JOB_HISTORY)

    if 'history' not in json_history:
        return 0

    if failures:
        tasks = json_history['history']['failedFinishedRuns']
    else:
        tasks = json_history['history']['successfulFinishedRuns']

    if quiet:
        if last and len(tasks) > 0:
            emitter.publish(tasks[0].get('id'))
        else:
            for task in tasks:
                emitter.publish(task.get('id'))
    elif json_flag:
        emitter.publish(tasks)
    else:
        emitter.publish(_get_history_message(json_history, job_id, failures))
        table = tables.job_history_table(tasks)
        if output := six.text_type(table):
            emitter.publish(output)

    return 0


def _get_history_message(json_history, job_id, failures):
    """
    :param json_history: json of history
    :type json_history: json
    :param job_id: Id of the job
    :type job_id: str
    :returns: history message
    :rtype: str
    """
    if failures:
        return f"'{job_id}'  Failure runs: {json_history['history']['failureCount']} Last Failure: {json_history['history']['lastFailureAt']}"

    else:
        return f"'{job_id}'  Successful runs: {json_history['history']['successCount']} Last Success: {json_history['history']['lastSuccessAt']}"


def _show(job_id):
    """
    :param job_id: Id of the job
    :type job_id: str
    :returns: process return code
    :rtype: int
    """

    try:
        client = metronome.create_client()
        json_job = client.get_job(job_id)
    except DCOSHTTPException as e:
        if e.response.status_code == 404:
            raise DCOSException(f"Job ID: '{job_id}' does NOT exist.")
        else:
            raise DCOSException(e)

    emitter.publish(json_job)

    return 0


def _show_runs(job_id, run_id=None, json_flag=False, quiet=False):
    """
    :param job_id: Id of the job
    :type job_id: str
    :returns: process return code
    :rtype: int
    """

    json_runs = _get_runs(job_id, run_id)
    if quiet is True:
        ids = _get_ids(json_runs)
        for run in ids:
            emitter.publish(run)
    elif json_flag is True:
        emitter.publish(json_runs)
    elif json_flag:
        emitter.publish(json_runs)
    elif _json_array_has_element(json_runs, 'id'):
        table = tables.job_runs_table(json_runs)
        if output := six.text_type(table):
            emitter.publish(output)
    else:
        emitter.publish(f"Nothing running for '{job_id}'")

    return 0


def _json_array_has_element(json_object, field):
    return any(field in element for element in json_object)


def _get_runs(job_id, run_id=None):
    """
    :param job_id: Id of the job
    :type job_id: str
    :returns: json of all running instance of a job_id
    :rtype: json
    """

    client = metronome.create_client()
    try:
        if run_id is None:
            return client.get_runs(job_id)
        else:
            return client.get_run(job_id, run_id)
    except DCOSException as e:
        raise DCOSException(e)


def _run(job_id, json_flag=False):
    """
    :param job_id: Id of the job
    :type job_id: str
    :returns: process return code
    :rtype: int
    """

    try:
        client = metronome.create_client()
        run_job = client.run_job(job_id)
    except DCOSHTTPException as e:
        if e.response.status_code == 404:
            emitter.publish(f"Job ID: '{job_id}' does not exist.")
        else:
            emitter.publish(f"Error running job: '{job_id}'")
    if json_flag:
        emitter.publish(run_job)
    else:
        emitter.publish(f"Run ID: {run_job['id']}")

    return 0


def _show_schedule(job_id, json_flag=False):
    """
    :param job_id: Id of the job
    :type job_id: str
    :returns: process return code
    :rtype: int
    """

    try:
        client = metronome.create_client()
        json_schedule = client.get_schedules(job_id)
    except DCOSHTTPException as e:
        if e.response.status_code == 404:
            raise DCOSException(f"Job ID: '{job_id}' does NOT exist.")
        else:
            raise DCOSException(e)
    except DCOSException as e:
        raise DCOSException(e)

    if json_flag:
        emitter.publish(json_schedule)
    else:
        table = tables.schedule_table(json_schedule)
        if output := six.text_type(table):
            emitter.publish(output)

    return 0


def parse_schedule_json(schedules_json):
    """
    The original design of metronome had an array of schedules defined but
    limited it to 1.  This limits to 1 and takes the array format or just
    1 schedule format.
    :param schedules_json: schedule or array of schedules in json
    :type schedules_json: json [] or {}
    :returns: schedule json
    :rtype: json
    """
    return schedules_json[0] if type(schedules_json) is list else schedules_json


def _add_schedules(job_id, schedules_json):
    """
    :param job_id: Id of the job
    :type job_id: str
    :param schedules_json: json for the schedules
    :type schedules_json: json
    :returns: process return code
    :rtype: int
    """

    if schedules_json is None:
        raise DCOSException('Schedule JSON is required.')

    schedule = parse_schedule_json(schedules_json)
    client = metronome.create_client()
    client.add_schedule(job_id, schedule)

    return 0


def _update_schedules(job_id, schedules_file):
    """
    :param job_id: Id of the job
    :type job_id: str
    :param schedule_id: Id of the schedule
    :type schedule_id: str
    :param schedule_file: filename for the schedule resource
    :type schedule_file: str
    :returns: process return code
    :rtype: int
    """
    schedules = _get_resource(schedules_file)
    schedule = parse_schedule_json(schedules)
    schedule_id = schedule['id']

    return _update_schedule(job_id, schedule_id, schedule)


def _update_schedule(job_id, schedule_id, schedule_json):
    """
    :param job_id: Id of the job
    :type job_id: str
    :param schedule_id: Id of the schedule
    :type schedule_id: str
    :param schedules_json: json for the schedules
    :type schedules_json: json
    :returns: process return code
    :rtype: int
    """

    if schedule_json is None:
        raise DCOSException("No schedule to update.")

    try:
        client = metronome.create_client()
        client.update_schedule(job_id, schedule_id, schedule_json)
        emitter.publish(f"Schedule ID `{schedule_id}` for job ID `{job_id}` updated.")
    except DCOSHTTPException as e:
        if e.response.status_code == 404:
            emitter.publish(
                f"Job ID: '{job_id}' or schedule ID '{schedule_id}' does NOT exist."
            )

    except DCOSException as e:
        raise DCOSException(e)

    return 0


def _add_schedule(job_id, schedule_file):
    """
    :param job_id: Id of the job
    :type job_id: str
    :param schedule_file: filename for the schedule resource
    :type schedule_file: str
    :returns: process return code
    :rtype: int
    """

    schedules = _get_resource(schedule_file)
    return _add_schedules(job_id, schedules)


def _add_job(job_file):
    """
    :param job_file: optional filename for the application resource
    :type job_file: str
    :returns: process return code
    :rtype: int
    """

    full_json = _get_resource(job_file)
    if full_json is None:
        raise DCOSException("No JSON provided.")

    if 'id' not in full_json:
        raise DCOSException("Jobs JSON requires an ID.")

    if 'disk' not in full_json['run']:
        full_json['run']['disk'] = 0

    job_id = full_json['id']
    schedules = None

    if 'schedules' in full_json:
        schedules = full_json['schedules']
        del full_json['schedules']

    client = metronome.create_client()
    client.add_job(full_json)

    return _add_schedules(job_id, schedules) if schedules is not None else 0


def _update_job(job_file):
    """
    :param job_file: filename for the application resource
    :type job_file: str
    :returns: process return code
    :rtype: int
    """
    # only updates the job (does NOT update schedules)
    full_json = _get_resource(job_file)
    if full_json is None:
        raise DCOSException("No JSON provided.")

    job_id = full_json['id']

    if 'schedules' in full_json:
        del full_json['schedules']

    try:
        client = metronome.create_client()
        client.update_job(job_id, full_json)
    except DCOSHTTPException as e:
        emitter.publish(f"Error updating job: '{job_id}'")

    return 0


def _info():
    """
    :returns: process return code
    :rtype: int
    """

    emitter.publish(default_command_info("job"))
    return 0


def _cli_config_schema():
    """
    :returns: schema for metronome cli config
    :rtype: dict
    """
    return json.loads(
        pkg_resources.resource_string(
            'dcos',
            'data/config-schema/job.json').decode('utf-8'))


def _do_request(url, method, timeout=None, stream=False, **kwargs):
    """
    make HTTP request

    :param url: url
    :type url: string
    :param method: HTTP method, GET or POST
    :type  method: string
    :param timeout: HTTP request timeout, default 3 seconds
    :type  timeout: integer
    :param stream: stream parameter for requests lib
    :type  stream: bool
    :return: http response
    :rtype: requests.Response
    """

    def _is_success(status_code):
        # consider 400 and 503 to be successful status codes.
        # API will return the error message.
        return status_code in [200, 400, 503]

    if timeout is None:
        timeout = _get_timeout()

    url = urllib.parse.urljoin(_get_metronome_url(), url)
    if method.lower() == 'get':
        http_response = http.get(url, is_success=_is_success,
                                 timeout=timeout, **kwargs)
    elif method.lower() == 'post':
        http_response = http.post(url, is_success=_is_success,
                                  timeout=timeout, stream=stream, **kwargs)
    elif method.lower() == 'delete':
        http_response = http.delete(url, is_success=_is_success,
                                    timeout=timeout, stream=stream, **kwargs)
    else:
        raise DCOSException(f'Unsupported HTTP method: {method}')
    return http_response


def _read_http_response_body(http_response):
    """
    Get an requests HTTP response, read it and deserialize to json.

    :param http_response: http response
    :type http_response: requests.Response onject
    :return: deserialized json
    :rtype: dict
    """

    data = b''
    try:
        for chunk in http_response.iter_content(1024):
            data += chunk
        return util.load_jsons(data.decode('utf-8'))
    except DCOSException:
        raise


def _get_ids(ids_json):
    """
    :param ids_json: json array of elements with ids
    :type ids_json: json
    :returns: set of ids
    :rtype: set
    """
    return [element['id'] for element in ids_json]


def _get_resource(resource):
    """
    :param resource: optional filename or http(s) url
    for the application or group resource
    :type resource: str
    :returns: resource
    :rtype: dict
    """
    if resource is not None:
        if os.path.isfile(resource):
            with util.open_file(resource) as resource_file:
                return util.load_json(resource_file)
        else:
            try:
                http.silence_requests_warnings()
                req = http.get(resource)
                if req.status_code != 200:
                    raise DCOSHTTPException(f"HTTP error code: {req.status_code}")
                data = b''
                for chunk in req.iter_content(1024):
                    data += chunk
                return util.load_jsons(data.decode('utf-8'))
            except Exception:
                logger.exception('Cannot read from resource %s', resource)
                raise DCOSException(
                    "Can't read from resource: {0}.\n"
                    "Please check that it exists.".format(resource))

    # Check that stdin is not tty
    if sys.stdin.isatty():
        # We don't support TTY right now. In the future we will start an
        # editor
        raise DCOSException(
            "We currently don't support reading from the TTY. Please "
            "specify an application JSON.\n"
            "E.g.: dcos job add < app_resource.json")

    return util.load_json(sys.stdin)


def _get_metronome_url(toml_config=None):
    """
    :param toml_config: configuration dictionary
    :type toml_config: config.Toml
    :returns: metronome base url
    :rtype: str
    """
    if toml_config is None:
        toml_config = config.get_config()

    metronome_url = config.get_config_val('metronome.url', toml_config)
    if metronome_url is None:
        # dcos must be capable to use dcos_url
        _check_capability()
        dcos_url = config.get_config_val('core.dcos_url', toml_config)
        if dcos_url is None:
            raise config.missing_config_exception(['core.dcos_url'])
        metronome_url = urllib.parse.urljoin(dcos_url, 'service/metronome/')

    return metronome_url


def _get_api_url(path):
    """
    :param path: service path
    :type path: str
    :returns: metronome base url
    :rtype: str
    """
    return urllib.parse.urljoin(_get_metronome_url(), path)


def _get_timeout():
    """
    :returns: timout value for API calls
    :rtype: str
    """
    return config.get_config_val('core.timeout') or DEFAULT_TIMEOUT
