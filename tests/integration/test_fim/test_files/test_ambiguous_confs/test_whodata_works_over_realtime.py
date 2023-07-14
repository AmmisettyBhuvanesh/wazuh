import sys
import pytest

from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.monitord.configuration import MONITORD_ROTATE_LOG
from wazuh_testing.modules.syscheck.configuration import SYSCHECK_DEBUG
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import file
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import TEST_CASES_PATH, CONFIGS_PATH


# Pytest marks to run on any service type on linux or windows.
pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=2)]

# Test metadata, configuration and ids.
cases_path = Path(TEST_CASES_PATH, 'cases_whodata_works_over_realtime.yaml')
config_path = Path(CONFIGS_PATH, 'configuration_whodata_works_over_realtime.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

# Set configurations required by the fixtures.
daemons_handler_configuration = {'all_daemons': True}
local_internal_options = {SYSCHECK_DEBUG: 2, AGENTD_DEBUG: 2, MONITORD_ROTATE_LOG: 0}
if sys.platform == WINDOWS: local_internal_options += {AGENTD_WINDOWS_DEBUG: 2}


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_whodate_works_over_realtime(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options,
                                     truncate_monitored_files, folder_to_monitor, daemons_handler):
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    test_file = Path(folder_to_monitor, test_metadata['test_file'])
    file.write_file(test_file)
    wazuh_log_monitor.start(callback=generate_callback(r'.*Sending FIM event:.*'))
    assert 'whodata' and 'added' in wazuh_log_monitor.callback_result
    
    file.remove_file(test_file)
    wazuh_log_monitor.start(callback=generate_callback(r'.*Sending FIM event:.*'))
    assert 'whodata' and 'deleted' in wazuh_log_monitor.callback_result