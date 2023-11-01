'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: This module verifies the correct behavior of 'wazuh-authd' under different messages
       in a Cluster scenario (for Master).

components:
    - authd

targets:
    - manager

daemons:
    - wazuh-authd
    - wazuh-db

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

tags:
    - enrollment
'''
import os
import subprocess
from pathlib import Path

import pytest

from wazuh_testing.constants.paths.sockets import WAZUH_DB_SOCKET_PATH, WAZUH_PATH
from wazuh_testing.utils.configuration import load_configuration_template, get_test_cases_data

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations

test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'config_authd_local.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_authd_local.yaml')
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)

# Variables
log_monitor_paths = []
ls_sock_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'sockets', 'auth'))
receiver_sockets_params = [(ls_sock_path, 'AF_UNIX', 'TCP'), (WAZUH_DB_SOCKET_PATH, 'AF_UNIX', 'TCP')]

daemons_handler_configuration = {'all_daemons': True}

# TODO Replace or delete
monitored_sockets_params = [('wazuh-db', None, True), ('wazuh-authd', None, True)]
receiver_sockets, monitored_sockets = None, None

# Fixtures
@pytest.fixture(scope='function')
def set_up_groups(test_metadata, request):
    """
    Set pre-existent groups.
    """

    groups = test_metadata['groups']

    for group in groups:
        if(group):
            subprocess.call(['/var/ossec/bin/agent_groups', '-a', '-g', f'{group}', '-q'])

    yield

    for group in groups:
        if(group):
            subprocess.call(['/var/ossec/bin/agent_groups', '-r', '-g', f'{group}', '-q'])


# Tests
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_authd_local_messages(test_configuration, test_metadata, set_wazuh_configuration, configure_sockets_environment,
                              connect_to_sockets_function, set_up_groups, insert_pre_existent_agents,
                              restart_wazuh_daemon_function, wait_for_authd_startup_function, tear_down):
    '''
    description:
        Checks that every input message in trough local authd port generates the adequate response to worker.

    wazuh_min_version:
        4.2.0

    tier: 0

    parameters:
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - configure_sockets_environment:
            type: fixture
            brief: Configure the socket listener to receive and send messages on the sockets at function scope.
        - connect_to_sockets_function:
            type: fixture
            brief: Bind to the configured sockets at function scope.
        - set_up_groups:
            type: fixture
            brief: Set the pre-defined groups.
        - insert_pre_existent_agents:
            type: fixture
            brief: adds the required agents to the client.keys and global.db
        - restart_authd_function:
            type: fixture
            brief: stops the wazuh-authd daemon
        - wait_for_authd_startup_function:
            type: fixture
            brief: Waits until Authd is accepting connections.
        - get_current_test_case:
            type: fixture
            brief: gets the current test case from the tests' list
        - tear_down:
            type: fixture
            brief: cleans the client.keys file

    assertions:
        - The received output must match with expected
        - The enrollment messages are parsed as expected
        - The agent keys are denied if the hash is the same as the manager's

    input_description:
        Different test cases are contained in an external YAML file (local_enroll_messages.yaml) which includes
        the different possible registration requests and the expected responses.

    expected_output:
        - Registration request responses on Authd socket
    '''
    cases = test_metadata['cases']
    for case in cases:
        # Reopen socket (socket is closed by manager after sending message with client key)
        receiver_sockets[0].open()
        expected = case['output']
        message = case['input']
        receiver_sockets[0].send(message, size=True)
        response = receiver_sockets[0].receive(size=True).decode()
        assert response[:len(expected)] == expected, \
            'Failed: Response was: {} instead of: {}' \
            .format(response, expected)