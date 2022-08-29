# Import the supporting Python packages.
import os
import string
import random
import pprint
import time as t
import argparse
from configparser import ConfigParser

# Import the havoc Python package.
import havoc

init_parser = argparse.ArgumentParser(description='havoc playbook - PowerShell Empire Builtin Host Recon')

init_parser.add_argument('--profile', help='Use a specific profile from your credential file')
init_args = init_parser.parse_args()

profile = init_args.profile

# Load the ./HAVOC configuration file
havoc_config = ConfigParser()
havoc_config_file = os.path.expanduser('~/.havoc/config')
havoc_config.read(havoc_config_file)

# Get api_key and secret_key
if profile:
    api_key = havoc_config.get(profile, 'API_KEY')
    secret = havoc_config.get(profile, 'SECRET')
    api_region = havoc_config.get(profile, 'API_REGION')
    api_domain_name = havoc_config.get(profile, 'API_DOMAIN_NAME')
else:
    api_key = havoc_config.get('default', 'API_KEY')
    secret = havoc_config.get('default', 'SECRET')
    api_region = havoc_config.get('default', 'API_REGION')
    api_domain_name = havoc_config.get('default', 'API_DOMAIN_NAME')

h = havoc.Connect(api_region, api_domain_name, api_key, secret)

# Configure pretty print for displaying output.
pp = pprint.PrettyPrinter(indent=4)

# Create a config parser and setup config parameters
config = ConfigParser(allow_no_value=True)
config.optionxform = str
config.read('havoc-playbooks/pse_host_recon/pse_host_recon.ini')

c2_task_name = config.get('c2_task', 'task_name')
c2_agent_name = config.get('c2_task', 'agent_name')

# Verify c2_task exists
print(f'\nVerifying that powershell_empire task {c2_task_name} exists.')
c2_task = h.verify_task(c2_task_name, 'powershell_empire')
if c2_task:
    print(f'C2 task {c2_task_name} found.')
else:
    exit(f'No powershell_empire task with name {c2_task_name} found. Exiting...')

# Verify that the C2 agent exists.
print(f'\nVerifying that agent {c2_agent_name} exists.')
agent = h.verify_agent(c2_task_name, c2_agent_name)
if agent:
    print(f'Agent {c2_agent_name} exists. Continuing...\n')
else:
    exit(f'Agent {c2_agent_name} not found. Exiting...\n')

# Execute the modules.
for section in config.sections():
    if section != 'c2_task':
        module_config = dict(config.items(section))
        if module_config['Enable'].lower() == 'true':
            module = module_config['Module']
            del module_config['Module']
            print(f'\nTasking agent with execute_module "{module}"\n')
            try:
                module_results = h.execute_agent_module(c2_task_name, c2_agent_name, module, module_config)
                print(f'{module} results:\n')
                print(module_results)
            except KeyboardInterrupt:
                print('Interrupting execute_agent_module. Skipping to next module...')

            # Wait for the powershell_empire task to become idle.
            print(f'\nWaiting for powershell_empire task {c2_task_name} to become idle.')
            try:
                h.wait_for_idle_task(c2_task_name)
            except KeyboardInterrupt:
                exit('Interrupting wait_for_idle_task. Exiting...')
            print(f'{c2_task_name} is now idle.')

# Playbook is complete.
exit('\nPlaybook operation completed. Exiting...')
