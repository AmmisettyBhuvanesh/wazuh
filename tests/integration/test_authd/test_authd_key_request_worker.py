'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: This module verifies the correct behavior of key request under different messages in a
       Cluster scenario (for Worker)

tier: 0

modules:
    - authd

components:
    - manager

daemons:
    - wazuh-authd
    - wazuh-clusterd

os_platform:
    - linux

os_version:
    - Amazon Linux 1
    - Amazon Linux 2
    - Arch Linux
    - CentOS 6
    - CentOS 7
    - CentOS 8
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 6
    - Red Hat 7
    - Red Hat 8
    - Ubuntu Bionic
    - Ubuntu Trusty
    - Ubuntu Xenial

tags:
    - key request
'''
import os

from pathlib import Path

import pytest
from wazuh_testing.modules.authd.utils import CLUSTER_DATA_HEADER_SIZE, cluster_msg_build
from wazuh_testing.constants.paths.sockets import MODULESD_C_INTERNAL_SOCKET_PATH, MODULESD_KREQUEST_SOCKET_PATH
from wazuh_testing.tools import mitm
from wazuh_testing.utils.configuration import load_configuration_template, get_test_cases_data

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]


# Configurations

class WorkerMID(mitm.ManInTheMiddle):

    def __init__(self, address, family='AF_UNIX', connection_protocol='TCP', func: callable = None):
        self.cluster_input = None
        self.cluster_output = None
        super().__init__(address, family, connection_protocol, self.verify_message)

    def set_cluster_messages(self, cluster_input, cluster_output):
        self.cluster_input = cluster_input
        self.cluster_output = cluster_output

    def verify_message(self, data: bytes):
        if len(data) > CLUSTER_DATA_HEADER_SIZE:
            message = data[CLUSTER_DATA_HEADER_SIZE:]
            response = cluster_msg_build(command=b'send_sync', counter=2, payload=bytes(self.cluster_output.encode()),
                                         encrypt=False)[0]
            print(f'Received message from wazuh-authd: {message}')
            print(f'Response to send: {self.cluster_output}')
            self.pause()
            return response
        else:
            raise ConnectionResetError('Invalid cluster message!')

    def pause(self):
        self.event.set()

    def restart(self):
        self.event.clear()


# Configurations
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'config_authd_key_request_worker.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_authd_key_request_worker.yaml')
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)

script_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'files')
script_filename = 'fetch_keys.py'

# Variables
receiver_sockets_params = [(MODULESD_KREQUEST_SOCKET_PATH, 'AF_UNIX', 'UDP')]
mitm_master = WorkerMID(address=MODULESD_C_INTERNAL_SOCKET_PATH, family='AF_UNIX', connection_protocol='TCP')
monitored_sockets_params = [('wazuh-clusterd', mitm_master, True), ('wazuh-authd', None, True)]
receiver_sockets, monitored_sockets = None, None


# Tests
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_authd_key_request_worker(test_configuration, test_metadata, set_wazuh_configuration,
                                  configure_sockets_environment, copy_tmp_script,
                                  connect_to_sockets_module):
    '''
    description:
        Checks that every message from the worker is correctly formatted for master,
        and every master response is correctly parsed for worker.

    wazuh_min_version:
        4.4.0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get the configuration of the test.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - configure_sockets_environment:
            type: fixture
            brief: Configure the socket listener to receive and send messages on the sockets.
        - copy_tmp_script:
            type: fixture
            brief: Copy the script to a temporary folder for testing.
        - connect_to_sockets_module:
            type: fixture
            brief: Bind to the configured sockets at module scope.
        - get_current_test_case:
            type: fixture
            brief: gets the current test case from the tests' list

    assertions:
        - The 'request_input' from agent is formatted to 'cluster_input' for master
        - The 'cluster_output' response from master is correctly parsed to 'port_output' for agent

    input_description:
        Different test cases are contained in an external YAML file (key_request_worker_messages.yaml) which includes
        the different possible key requests and the expected responses.

    expected_output:
        - Registration request responses on Authd socket
    '''
    key_request_sock = receiver_sockets[0]
    clusterd_queue = monitored_sockets[0]

    # Push expected info to mitm queue
    mitm_master.set_cluster_messages(test_metadata['cluster_input'], test_metadata['cluster_output'])
    mitm_master.restart()
    message = test_metadata['request_input']
    key_request_sock.send(message, size=False)
    # callback lambda function takes out tcp header and decodes binary to string
    results = clusterd_queue.get_results(callback=(lambda y: [x[CLUSTER_DATA_HEADER_SIZE:].decode() for x in y]),
                                            timeout=1, accum_results=1)
    # Assert monitored sockets
    assert results[0] == test_metadata['cluster_input'], 'Expected clusterd input message does not match'
    assert results[1] == test_metadata['cluster_output'], 'Expected clusterd output message does not match'