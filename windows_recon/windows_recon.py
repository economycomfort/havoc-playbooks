# Import the supporting Python packages.
import re
import os
import json
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


# Poll the task_details until the task's status 'idle'.
def get_task_status(tn):
    task_status = None
    task_details = None
    while task_status != 'idle':
        t.sleep(5)
        task_details = h.get_task(tn)
        task_status = task_details['task_status']
    print(f'\n{tn} is ready:')
    pp.pprint(task_details)
    return task_details


# A 'while loop' can be used to continually pull the results queue until the command results are returned.
def get_command_results(tn, ic, ii, print_output=True):
    results = []
    command_finished = None
    try:
        while not command_finished:
            command_results = h.get_task_results(tn)
            if 'queue' in command_results:
                for entry in command_results['queue']:
                    if entry['instruct_command'] == ic and entry['instruct_instance'] == ii:
                        command_finished = True
                        if print_output:
                            print(f'\n{tn} {ic} results:')
                            pp.pprint(entry)
                        results.append(entry)
            if not command_finished:
                t.sleep(5)
    except KeyboardInterrupt:
        exit('get_command_results interrupted. Exiting...')
    return results


# Verify c2_task exists
print(f'\nVerifying that C2 task {c2_task_name} exists.')
task_list = h.list_tasks()
if c2_task_name in task_list['tasks']:
    c2_task_details = h.get_task(c2_task_name)
    if c2_task_details['task_type'] == 'powershell_empire':
        print(f'C2 task {c2_task_name} found.')
    else:
        exit(f'{c2_task_name} found but task_type is not "powershell_empire" - exiting...')
else:
    exit(f'C2 task {c2_task_name} does not exist. Exiting...')

# Verify remote_ad_task_name exists
print(f'\nVerifying that trainman task {remote_ad_task_name} exists.')
target_ip = None
task_list = h.list_tasks()
if remote_ad_task_name in task_list['tasks']:
    remote_ad_task_details = h.get_task(remote_ad_task_name)
    if remote_ad_task_details['task_type'] == 'trainman':
        print(f'Trainman task {remote_ad_task_name} found.')
    else:
        exit(f'{remote_ad_task_name} found but task_type is not "trainman" - exiting...')
    target_ip = get_task_target_ip(remote_ad_task_name)
else:
    exit(f'\nTrainman task {remote_ad_task_name} does not exist. Exiting...')

# Execute a list of shell commands on the agent.
results_count = 0
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
    h.instruct_task(c2_task_name, sc_instruct_instance, instruct_command, instruct_args)

    # Get the agent_shell_command confirmation.
    print(f'\nWaiting for confirmation of agent_shell_command "{shell_command}".\n')
    shell_command_confirmation = get_command_results(c2_task_name, instruct_command, sc_instruct_instance)
    for sc_conf in shell_command_confirmation:
        if sc_conf['instruct_command'] == instruct_command and sc_conf['instruct_instance'] == sc_instruct_instance:
            instruct_command_output = json.loads(sc_conf['instruct_command_output'])
            if instruct_command_output['outcome'] == 'success':
                print(f'{shell_command} succeeded.\n')
            else:
                print(f'{shell_command} failed.\n')

    # Get the agent_shell_command results.
    print(f'\nGetting results from agent_shell_command "{shell_command}"\n')
    results = None
    while not results:
        try:
            instruct_command = 'get_shell_command_results'
            instruct_args = {'Name': c2_agent_name}
            h.instruct_task(c2_task_name, sc_instruct_instance, instruct_command, instruct_args)

            # Get the output from the get_shell_command_results command.
            shell_command_results = get_command_results(c2_task_name, instruct_command, sc_instruct_instance, False)
            for sc_result in shell_command_results:
                if sc_result['instruct_command'] == instruct_command and \
                        sc_result['instruct_instance'] == sc_instruct_instance:
                    instruct_command_output = json.loads(sc_result['instruct_command_output'])
                    if instruct_command_output['outcome'] == 'success':
                        results = instruct_command_output['results'][results_count]['results']
                    else:
                        results = f'{shell_command} failed.\n'
            if not results:
                t.sleep(10)
        except KeyboardInterrupt:
            exit('get_command_results interrupted. Exiting...')
    print(f'\n{shell_command} results:\n')
    print(results)
    results_count += 1

    # Wait for the powershell_empire task to become idle.
    print(f'\nWaiting for powershell_empire task {c2_task_name} to become idle.')
    pse_task_status = get_task_status(c2_task_name)
    print(f'\n{c2_task_name} is now idle.')
    t.sleep(random.randrange(20))

# Playbook is complete.
exit('\nPlaybook operation completed. Exiting...')
