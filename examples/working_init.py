""" standard """
import ConfigParser
import sys

""" custom """
from threatconnect import *
from threatconnect.Config.IndicatorType import IndicatorType

# configuration file
# config_file = "../tc.conf"
# config_file = "../tc_tcdev-test.conf"
config_file = "../tc-sumx-us.conf"

# read configuration file
config = ConfigParser.RawConfigParser()
config.read(config_file)

try:
    api_access_id = config.get('threatconnect', 'api_access_id')
    api_secret_key = config.get('threatconnect', 'api_secret_key')
    api_default_org = config.get('threatconnect', 'api_default_org')
    api_base_url = config.get('threatconnect', 'api_base_url')
    api_max_results = config.get('threatconnect', 'api_max_results')
except ConfigParser.NoOptionError:
    print('Could not read configuration file.')
    sys.exit(1)

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url, api_max_results)