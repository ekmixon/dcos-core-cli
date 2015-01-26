import json

import requests
from dcos.api import errors


class Client(object):
    """Class for talking to the Marathon server. """

    def __init__(self, host, port):
        """Constructs interface for talking Marathon.

        :param host: Host for the Marathon server.
        :type host: str
        :param port: Port for the Marathon server.
        :type port: int
        """

        self._url_pattern = "http://{host}:{port}/{path}"
        self._host = host
        self._port = port

    def _create_url(self, path):
        """Creates the url from the provided path

        :param path: Url path
        :type path: str
        :returns: Constructed url
        :rtype: str
        """

        return self._url_pattern.format(
            host=self._host,
            port=self._port,
            path=path)

    def _sanitize_app_id(self, app_id):
        """
        :param app_id: Raw application ID
        :type app_id: str
        :returns: Sanitized application ID
        :rtype: str
        """

        # Add a leading '/' if necessary.
        if not app_id.startswith('/'):
            app_id = '/' + app_id
        return app_id

    def _response_to_error(self, response):
        """
        :param response: HTTP resonse object
        :type response: requests.Response
        :returns: The error embedded in the response JSON
        :rtype: Error
        """

        return Error('Error: {}'.format(response.json()['message']))

    def get_app(self, app_id):
        """Returns a representation of the requested application.
        :param app_id: The ID of the application.
        :type app_id: str
        :returns: The requested Marathon application
        :rtype: (dictionary, Error)
        """

        app_id = self._sanitize_app_id(app_id)

        url = self._create_url('v2/apps' + app_id)
        response = requests.get(url)

        if response.status_code == 200:
            app = response.json()['app']
            return (app, None)
        else:
            return (None, self._response_to_error(response))

    def get_apps(self):
        """Get a list of known applications.
        :returns: List of known applications.
        :rtype: (list of dictionaries, Error)
        """

        url = self._create_url('v2/apps')
        response = requests.get(url)

        if response.status_code == 200:
            apps = response.json()['apps']
            return (apps, None)
        else:
            return (None, self._response_to_error(response))

    def start_app(self, app_resource):
        """Create and start a new application.

        :param app_resource: Application resource
        :type app_resource: dict, bytes, or file
        :returns: Status of trying to start the application
        :rtype: (bool, Error)
        """

        url = self._create_url('v2/apps')
        response = requests.post(url, data=app_resource)

        if response.status_code == 201:
            return (True, None)
        else:
            return (None, self._response_to_error(response))

    def scale_app(self, app_id, instances, force=None):
        """Scales an application to the requested number of instances.
        :param app_id: The ID of the application to scale.
        :type app_id: str
        :param instances: The requested number of instances.
        :type instances: int
        :param force: Whether to override running deployments.
        :type force: bool
        :returns: The resulting deployment ID.
        :rtype: (bool, Error)
        """

        if force is None:
            force = False

        app_id = self._sanitize_app_id(app_id)

        forceQuery = ''
        if force:
            forceQuery = '?force=true'

        url = self._create_url('v2/apps' + app_id + forceQuery)
        scale_json = json.loads('{{ "instances": {} }}'.format(int(instances)))
        response = requests.put(url, json=scale_json)

        if response.status_code == 200:
            deployment = response.json()['deploymentId']
            return (deployment, None)
        else:
            return (None, self._response_to_error(response))

    def suspend_app(self, app_id, force=None):
        """Scales an application to zero instances.
        :param app_id: The ID of the application to suspend.
        :type app_id: str
        :param force: Whether to override running deployments.
        :type force: bool
        :returns: The resulting deployment ID.
        :rtype: (bool, Error)
        """

        return self.scale_app(app_id, 0, force)

    def remove_app(self, app_id):
        """Completely removes the requested application.
        :param app_id: The ID of the application to suspend.
        :type app_id: str
        :returns: Status of trying to remove the application.
        :rtype: (bool, Error)
        """

        app_id = self._sanitize_app_id(app_id)

        url = self._create_url('v2/apps' + app_id + '?force=true')
        response = requests.delete(url)

        if response.status_code == 200:
            return (True, None)
        else:
            return (None, self._response_to_error(response))


class Error(errors.Error):
    def __init__(self, message):
        """Constructs error for Marathon calls

        :param message: Error message
        :type message: str
        """

        self._message = message

    def error(self):
        """Return error message

        :returns: The error message
        :rtype: str
        """

        return self._message
