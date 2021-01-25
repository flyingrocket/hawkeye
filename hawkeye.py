#! /usr/bin/env python3

#################################################
# Import libraries
#################################################
# parse cli arguments
import argparse
# caclulate a md5sum
import hashlib
# date, time
import datetime
# read the json file
import json
# status codes
import requests
# read dirs and files
import os.path
# create a unique identifier per session
import uuid
# monkey
import random
# regular expressions
import re
# send mails
import smtplib
# get the hostname, network connection
import socket
# system calls
import sys
# move files to other dirs
import shutil
# to get file age
import stat
# time scripts
import time
# http requests:
# $ apt install python3-urllib3
import urllib3
# yaml supprt
import yaml

#################################################
# Import 3d party libs
#################################################
# include 3d party libraries: add the lib/ dir to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))
# progress bar
from progress.bar import Bar

#################################################
# Import classes and functions
#################################################
# main app class
from classes.App import App

# functions
from functions.DesktopNotify import desktop_notify
from functions.PrettyTitle import pretty_title


#################################################
# Script context
#################################################
abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

#################################################
# Build session
#################################################
session = {}
session['dir'] = os.path.dirname(__file__)
session['id'] = str(uuid.uuid4())

#################################################
# Create session hash
#################################################
argument_list_hash = sys.argv[1:]
# do not hash debugmode
hash_blacklist = ['-d', '--debug', '-v', '--version']

for option in hash_blacklist:
    if option in argument_list_hash:
        argument_list_hash.remove(option) # remove these options for the hash

session['hash'] = hashlib.md5('.'.join(argument_list_hash).encode('utf-8')).hexdigest()

#################################################
# App version
#################################################
App = App(session['hash'])

app_version = App.version
app_name = App.name
app_full_version = App.full_version

app_version_line = 'Version: {} {}'.format(app_name, app_full_version)
app_hash_line = 'Hash/ID: {} {}'.format(session['hash'], session['id'])

#################################################
# Time script
#################################################
date_stamp = str(datetime.datetime.now().date())
format = '%Y-%m-%d_%H%M%S'
datetime_stamp = str(datetime.datetime.now().strftime(format))

# time the script
start_time = time.time()

#################################################
# Parse cli arguments
#################################################
# check version
if len(sys.argv) > 1:
    if sys.argv[1] == '-v' or sys.argv[1] == '--version':
        print(app_full_version)
        App.quit()

# -----------------------------------------------
# Arguments
# -----------------------------------------------
parser = argparse.ArgumentParser(description=app_name + app_version)
# all the services 
parser.add_argument('-s', '--servicesfile', help='services json or yaml file', required=True)
# main config, set to default if not specified
parser.add_argument('-c', '--configfile', help='config json or yaml file', required=False, default=os.path.join(session['dir'], 'config/default.config.yaml'))
# log path
parser.add_argument('-l', '--logpath', help='log path to store hawkeye statuses', required=False, default='/tmp')

# -----------------------------------------------
# Flags
# -----------------------------------------------
parser.add_argument('-m', '--monkey', help='monkey mode', required=False, default=False, action='store_true')
parser.add_argument('-d', '--debug', help='debug mode', required=False, default=False, action='store_true')
parser.add_argument('-t', '--tag', help='tag, e.g. server name', required=False, default=False)
parser.add_argument('-v', '--version', help='version', required=False, action='store_true')
parser.add_argument('--quiet', help='Do not send e-mails', required=False, default=False, action='store_true')
args = parser.parse_args()

#################################################
# Debug
#################################################
monkey = False

# debugmode
if args.debug:
    debugmode = True
    # randomize values when in debug
    if args.monkey:
        monkey = True
else:
    debugmode = False

#################################################
# Pre-flight checks
#################################################

# -----------------------------------------------
# Check if config files exist
# -----------------------------------------------
for file_path in [args.configfile, args.servicesfile]:
    if not os.path.isfile(file_path) and not os.path.islink(file_path):
        App.fail('Abort! Cannot access {}!'.format(file_path))


cli_params = {}
cli_params['services'] = args.servicesfile
cli_params['config'] = args.configfile

# -----------------------------------------------
# Validate config file format
# -----------------------------------------------
for type, file_path in cli_params.items():
    if not os.path.isfile(file_path):
        App.fail('{} file not found!'.format(type))

    with open(file_path) as file:
        if re.search('.+\.json$', file_path):
            try:
                session[type] = json.load(file)
            except:
                App.fail('Exception in parsing json file ' + file_path + '!')
        elif re.search('.+\.ya?ml$', file_path):
            try:
                session[type] = yaml.load(file, Loader=yaml.SafeLoader)
            except:
                App.fail('Exception in parsing yaml file ' + file_path + '!')
        else:
            App.fail('{} file not supported!'.format(type))

    # sort the files
    cli_config_tmp = {}
    keys = sorted(list(session[type].keys()))
    for k in keys:
        cli_config_tmp[k] = session[type][k]
    session[type] = cli_config_tmp

# -----------------------------------------------
# Get global defaults
# -----------------------------------------------
session_defaults = {}
file_path = './config/default.config.yaml'
with open(file_path) as file:
    try:
        session_defaults = yaml.load(file, Loader=yaml.SafeLoader)
    except:
        App.fail('Exception in parsing default condig yaml file ' + file_path + '!')

# -----------------------------------------------
# Check if dirs exist
# -----------------------------------------------
# check if dirs exist!
for type in ['log', 'tmp']:
    try:
        dir = os.path.expanduser(session['config']["dirs"][type])
    except:
        App.fail('Abort! Directive dir:{} not set??'.format(type))
    # use expanduser to deal with a tilda
    if os.path.isdir(dir) != True:
        App.fail("Abort! {} dir {} not found!".format(type, dir))

# set the variables
log_dir = os.path.normpath(os.path.expanduser(session['config']["dirs"]["log"]))
tmp_dir = os.path.normpath(os.path.expanduser(session['config']["dirs"]["tmp"]))

# -----------------------------------------------
# Validate trigger
# -----------------------------------------------
if not session['config']['desktop']['trigger'] in ['warning', 'change']:
    App.fail("Abort! Desktop trigger must be value warning|change")

#################################################
# Kick-off
#################################################
App.init_lock()

# app version
print(app_version_line)
print(app_hash_line)
print()

#################################################
# Iterate services
#################################################

# -----------------------------------------------
# Debug
# -----------------------------------------------
# randomize services for debugging
if monkey:
    print()
    print(pretty_title('Monkey'))
    print()
    services = list(session['services'].keys())
    random_service =  random.choice(services)
    print()
    print('--> Monkey deleted service {} :)'.format(random_service))
    session['services'].pop(random_service, None)

# -----------------------------------------------
# Use urllib3 lib
# -----------------------------------------------
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings()

# create the http object
http = urllib3.PoolManager(maxsize=100, block=True)

services_failed = {}
configured_services_per_recipient = {}

number_of_services = len(session['services'].items())

# -----------------------------------------------
# Prepare, set defaults
# -----------------------------------------------
print('Check status for {} services...'.format(number_of_services))
print()

# create the progress bar
bar = Bar('Scanning...', max=number_of_services)

# -----------------------------------------------
# Compile urls
# -----------------------------------------------
# create temporary services dict 
services_tmp = {}

# allow for www.google.com with a specified protocol
for service, service_config in session['services'].items():

    ## TODO: this check is redundant with same check in service loop later
    directive = 'protocol'
    # set global directive as default
    if directive in session['config']['request'].keys():
        protocol = session['config']['request'][directive]
    else:
        protocol = session_defaults['request'][directive]

    if service_config:
        # override per service
        if directive in service_config:
            protocol = service_config[directive]

    url_stripped = re.sub(r'https?://', '', service )

    # no protocol in URL (no http(s)://)
    if service == url_stripped:
        if protocol == 'http':
            service_url = 'http://' + url_stripped
        elif protocol == 'https':
            service_url = 'https://' + url_stripped
        else:
            App.fail('Invalid protocol for service {}!'.format(service))
    # protocol in URL
    else:        
        service_url = service

    services_tmp[service_url] = session['services'][service]
    # a_dict[new_key] = a_dict.pop(old_key)

session['services'] = services_tmp

# -----------------------------------------------
# Loop through services
# -----------------------------------------------
messages=[]
responses = {}
rules = {}
request_params = {}

connectivity_checked = False

# request the urls
for service, service_config in session['services'].items():
    
    # rules per service
    rules[service] = []

    # initiate status
    service_status = False

    # get a list of all http response codes
    response_codes = requests.status_codes._codes

    # -----------------------------------------------
    # Match tags
    # -----------------------------------------------
    # skip if tags do not match
    if args.tag and 'tag' in service_config:
        if args.tag != service_config['tag']:
            messages.append('Skipped ' + service + ' (tagged "' + service_config['tag'] + '")...')
            bar.next()
            continue
    
    # -----------------------------------------------
    # Debug
    # -----------------------------------------------
    if monkey:
        # randomly change a service
        if random.randint(0, 1) == 1:
            request_params['status'] = random.choice(list(response_codes.keys()))

    # -----------------------------------------------
    # Override global directives
    # -----------------------------------------------
    for directive in ['redirect', 'timeout', 'retries', 'status', 'protocol']:

        # set global directive as default
        if directive in session['config']['request'].keys():
            request_params[directive] = session['config']['request'][directive]
        else:
            request_params[directive] = session_defaults['request'][directive]

        if service_config:
          # override per service
          if directive in service_config:
              request_params[directive] = service_config[directive]
       
    for directive in ['redirect', 'status']:        
        rules[service].append(directive + '=' + str(request_params[directive]))

    # -----------------------------------------------
    # Check for network
    # -----------------------------------------------
    # check connectivity
    if not connectivity_checked:
        domain = service.split('//')[-1].split('/')[0].split('?')[0]
        try:
            # print('Connectivity check. Try {}... '.format(domain))
            resolved = socket.gethostbyname('8.8.8.8')
        except OSError as e:
            App.fail('Network connection failed! Cannot resolve {}. Error: "{}"...'.format(domain, e.args[1]))
        
        connectivity_checked = True

    # -----------------------------------------------
    # Validate url
    # -----------------------------------------------

    # regex to validate url
    regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    # validate url
    url_is_valid = re.match(regex, service)
    if not url_is_valid:
        App.fail('URL {} is not valid!'.format(service))

    # -----------------------------------------------
    # Make the request
    # -----------------------------------------------
    # check the response
    try:
        user_agent = app_name + " " + app_version

        r = http.request('GET', service, redirect=request_params['redirect'], timeout=float(request_params['timeout']), retries=int(request_params['redirect']), headers ={
            'User-Agent': user_agent
            }
            )
        responses[service] = r.status
    except Exception as e:
        services_failed[service] = 'FAILED CONNECTION'# + str(e) # do not use the error message, it causes problems trying to parse the file!
        responses[service] = '***'      

    # -----------------------------------------------
    # Validate response 
    # -----------------------------------------------
    if service not in services_failed.keys():
        # add to failure list if response does not match
        if r.status != request_params['status']:
            services_failed[service] = 'FAILED RESPONSE {} "{}", received {} "{}"'.format(str(request_params['status']), response_codes[int(request_params['status'])][0], str(r.status), response_codes[int(r.status)][0])
        # extra check: check if hash matches expected hash
        elif service_config and 'hash' in service_config:
            # $ wget https://some.url, $ cat index.html | md5sum
            hash_expected = service_config['hash']
            text = r.data.decode("utf-8")
            text_utf8 = text.encode("utf-8")
            md5_hash = hashlib.md5(text_utf8)
            hash_calculated = md5_hash.hexdigest()
            if hash_calculated != hash_expected:
                services_failed[service] = 'FAILED MD5SUM "{}", received "{}"'.format(service_config['hash'], str(hash_calculated))

    # -----------------------------------------------
    # Setup notifications
    # -----------------------------------------------
    # build an array of all recipients and their services
    if session['config']['email']['enabled']:
        # check if secondary recipients need to be added
        if 'services' in session['config']['email'].keys() and session['config']['email']['services'] == True:
            search_config_files = [service_config, session['config']]
        else:
            search_config_files = [session['config']]
        # iterate
        for config in search_config_files:
            # setup notices
            if 'notify' in config:
                for recipient in config['notify']:
                    # check if email already exists
                    if not recipient in configured_services_per_recipient.keys():
                        configured_services_per_recipient[recipient] = []
                    # add this service
                    configured_services_per_recipient[recipient].append(service)
    bar.next()
bar.finish()


#################################################
# Rules
#################################################
print()
print(pretty_title('Service Rules'))
print()

#print(responses) 
for service, rules in rules.items():
    print(service.ljust(60, '.'), ','.join(rules))

#################################################
# Responses
#################################################
print()
print(pretty_title('Service Response'))
print()

#print(responses) 
for service, response in responses.items():
    print(service.ljust(60, '.'), response)
    
#################################################
# Service history
#################################################
history_tmp_file = os.path.join(args.logpath, app_name + '.' + session['hash'] + '.history')

try:
    with open(history_tmp_file) as file:
        history_list = yaml.load(file, Loader=yaml.SafeLoader)
        # Do something with the file
except IOError:
    history_list = {}
#
# # write the file if it doesn't exist
# file = open(history_tmp_file, 'a+') # do not use w+ because getsize will not work
# file.close()
#
# if os.path.getsize(history_tmp_file) == 0:
#     print('file is empty')
#     history_list = {}
# else:
#     print('read from file')
#     with open(history_tmp_file) as file:
#         history_list = yaml.load(file, Loader=yaml.FullLoader)

# -----------------------------------------------
# Debug
# -----------------------------------------------
if debugmode:
    print()
    print('Old service history:')
    print(history_list)

#################################################
# Failed services
#################################################
if len(services_failed.items()):
    print()
    print(pretty_title('Failed Services'))
    print()

    for service, reply in services_failed.items():
        print(service.ljust(60, '.'), reply)

#################################################
# Succesive failures
#################################################
# keep sucessive failures
for service, service_config in session['services'].items():
    if service in services_failed.keys():
        if service in history_list:
            history_list[service] += 1
        else:
            history_list[service] = 1
    else:
        history_list[service] = 0

file = open(history_tmp_file, 'w+')
history_dumped = yaml.dump(history_list, file)

# -----------------------------------------------
# Debug
# -----------------------------------------------

# print('Failed ervices')
# print(services_failed.keys())
#
# if len(services_failed.keys()):
#     print('yes, there are failed services')

if debugmode:
    print('New service history:')
    print(history_list)

# -----------------------------------------------
# Successive failure logic
# -----------------------------------------------
# make a copy of the failed services
services_failed1 = dict(services_failed)

if len(services_failed1.keys()) > 0:
    print()
    print('Successive faiures:')
    
    # TODO create a function to look up defaults
    if 'successive_failures' in session['config']['notify_when'].keys():
        successive_failures = session['config']['notify_when']['successive_failures']
    else:
        successive_failures = session_defaults['notify_when']['successive_failures']

    for service in services_failed1.keys():
        print(service.ljust(60, '.'), history_list[service])
        if history_list[service] < successive_failures:
            del services_failed[service]
            print('*** WARNING *** This failure ({}) did not reach threshold ({}). Removing notification...'.format(history_list[service], successive_failures))

# -----------------------------------------------
# Debug
# -----------------------------------------------
if debugmode:
    print()
    print('All services per mail address...')
    print(configured_services_per_recipient)

# -----------------------------------------------
# Print messages
# -----------------------------------------------
# print messages
if len(messages):
    print()
    for m in messages:
        print(m)

#################################################
# Service status
#################################################
print()
print(pretty_title('Service Status'))
print()

# -----------------------------------------------
# Write to log
# -----------------------------------------------
services_tmp_file_path = os.path.join(tmp_dir, app_name + '.' + session['hash'] + '.' + datetime_stamp + '.' + session['id'] + '.services.tmp')
# print('Write tmp file... {}'.format(services_tmp_file_path))
services_tmp_file_handle = open(services_tmp_file_path, 'w')

services_log_file_path = os.path.join(log_dir, app_name + '.' + date_stamp + '.services.log')
# status_log_file_path = os.path.join(log_dir, script_name + '.status.log')
print('Write log file... {}'.format(services_log_file_path))
print()
services_log_file_handle = open(services_log_file_path, 'a')

# -----------------------------------------------
# Print service status
# -----------------------------------------------
for service, service_config in session['services'].items():
    if service in services_failed.keys():
        print(service.ljust(60, '.'), 'FAIL')
    else:
        print(service.ljust(60, '.'), 'PASS')

#################################################
# Global status
#################################################
print()
print(pretty_title('Global Status'))
print()

# -----------------------------------------------
# Write to log
# -----------------------------------------------
# iterate through all services
for service, service_config in session['services'].items():
    if service in services_failed:
        new_status = services_failed[service]
    else:
        new_status = 'PASS'

    line = datetime_stamp + ';' + session['id'] + ';' + service + ';' + new_status + "\n"
    services_tmp_file_handle.write(line)
    services_log_file_handle.write(line)

# close files
services_tmp_file_handle.close()
services_log_file_handle.close()

# -----------------------------------------------
# Print global status
# -----------------------------------------------
# print final status
if len(services_failed) == 0:
    global_status = 'PASS'
else:
    global_status = 'FAIL'

print('Global Status'.ljust(60, '.'), global_status)

#################################################
# Logic for changed services
#################################################

# -----------------------------------------------
# Handle temporary files
# -----------------------------------------------
# get a list of all files in tmp dir
tmp_files_listing = os.listdir(tmp_dir)

# add all the service tmp files to a list
service_tmp_files = []
for file in tmp_files_listing:
    if re.search(app_name + '.' + session['hash'] + '.+\.services\.tmp$', file):
        service_tmp_files.append(file)

# reverse sort to keep latest files
service_tmp_files.sort(reverse=True)

# remove old tmp files
i=2 # keep 2 files
while i < len(service_tmp_files):
    file_path = os.path.join(tmp_dir, service_tmp_files[i])
    # print('Removing old tmp file {}...'.format(file_path))
    os.remove(file_path)
    i += 1

# -----------------------------------------------
# Detect changed services
# -----------------------------------------------
changed_services = {}
# script is ran for the first time (or after reboot)
if len(service_tmp_files) == 1:
    print('No old runs detected...')
else:
    # store the statuses
    service_status_log = {}
    i = 0
    for run in ['new', 'old']:

        service_log_file_path = os.path.join(tmp_dir, service_tmp_files[i])
        # open the files
        service_log_file_handle = open(service_log_file_path, 'r')

        # store the contents of the files in a list
        service_log_lines = service_log_file_handle.readlines()

        # store the contents of the lists in a associative dictionary
        service_status_log[run] = {}

        ii = 0
        while ii < len(service_log_lines):
            # new services
            line = service_log_lines[ii].strip()
            p = line.split(';')
            service = p[2]
            status = p[3]
            service_status_log[run][service] = status
            ii += 1

        i += 1

    # -----------------------------------------------
    # Compare status
    # -----------------------------------------------
    for service, new_status in service_status_log['new'].items():
        # do not compare a new service
        if not service in service_status_log['old']:
            changed_services[service] = new_status
            print('New service detected... {}'.format(service))
        elif not service_status_log['new'][service] == service_status_log['old'][service]:
            changed_services[service] = new_status
            print('Change in service detected... {}'.format(service))

# -----------------------------------------------
# Print info
# -----------------------------------------------
if len(changed_services) == 0:
    print('No changes since last run...')

#################################################
# Desktop alerts
#################################################
notify_desktop = False
if session['config']['desktop']['enabled']:
    if session['config']['desktop']['trigger'] == 'change':
        if len(changed_services) != 0:
            notify_desktop = True
    # contiuous notifications
    else:
        if global_status == 'FAIL':
            notify_desktop = True

if notify_desktop:
    desktop_notify(messages)

#################################################
# Compile mailing list
#################################################
print()
print(pretty_title('Notifications'))
print()

# -----------------------------------------------
# Set e-mail notification
# -----------------------------------------------
notify_email = False

# allow a quiet cli run - sending no emails 
if args.quiet:
    print('Quiet mode is set. E-mails disabled...')
else:
    if session['config']['email']['enabled']:
        if len(changed_services) != 0:
            if global_status == 'PASS' and session['config']['notify_when']['services_passed'] != True:
                notify_email = False
            else:
                notify_email = True

# -----------------------------------------------
# Debug
# -----------------------------------------------
if debugmode:
    if len(changed_services) != 0:
        print(pretty_title('Changed Services', 'h3'))
        print()
        print(changed_services)
        print()

#################################################
# Send e-mails
#################################################
# send messages
if notify_email:
    if debugmode:
        print('Send notifcations (simulated)...')
    else:
        print('Send notifications (e-mail)...')

    print()

    changed_service_recipients = []
    # check all services per recipent for changes
    for recipient, services in configured_services_per_recipient.items():
        # check if changed
        for service in services:
            if service in changed_services:
                # check if in dict
                if not recipient in changed_service_recipients:
                    changed_service_recipients.append(recipient)
                    break

    if debugmode:
        if len(changed_service_recipients) != 0:
            print(pretty_title('Notify Recipients', 'h3'))
            print()
            print(changed_service_recipients)
            print()

    # log mails - purely for debugging
    mail_log_file_path = os.path.join(args.logpath, app_name + '.' + session['hash'] + '.' + datetime_stamp + '.' + session['id'] + '.mail.log')
    print('Write mail log file... {}'.format(mail_log_file_path ))
    mail_log_file_handle = open(mail_log_file_path, 'a')
    print()

    # -----------------------------------------------
    # Prepare messages
    # -----------------------------------------------
    mails = {}
    for recipient in changed_service_recipients:
        # setup mail variables
        mails[recipient] = {}
        failures = 0
        body = []

        body.append(app_version_line)
        body.append(app_hash_line)
        body.append('')
        body.append('Verifying services...')
        body.append('')

        list_of_services = []
        # iterate all services
        for service in configured_services_per_recipient[recipient]:
            if service in services_failed.keys():
                failures += 1
                indent = "*** fail *** "
                newline = '' # '"\n"
            else:
                indent = ''
                newline = ''

            # append all services to body
            list_of_services.append(newline + indent + service + " " + service_status_log['new'][service] + newline)

        if failures:
            status = str(failures) + ' SERVICE(S) FAILED!'
        else:
            status = 'SERVICES PASSED'

        list_of_services.sort()

        for service_line in list_of_services:
            body.append(service_line)

        hostname = socket.gethostname()
        subject = app_name.upper() + ' @' + hostname + ' ' + status

        mails[recipient]['subject'] = subject
        mails[recipient]['body'] = body

    # -----------------------------------------------
    # Send e-mails
    # -----------------------------------------------
    # iterate all mails
    fqdn = socket.getfqdn()

    i=1
    for recipient in mails.keys():

        sender = app_name + '@' + fqdn

        message = []
        message.append('From: <' + sender + '>')
        message.append('To: <' + recipient + '>')
        message.append('Subject: ' + mails[recipient]['subject'])
        # newline between subject and message?
        message.append('')
        for line in mails[recipient]['body']:
            message.append(line)

        #message.append('')
        #message.append('Run ID: {}'.format(session['id']))

        if debugmode:
            print('------ MAIL {} ------'.format(i))
            print(' --- ', end='')
            print("\n --- ".join(message))
            print('---')

        else:
            try:
                print('Sending mails to server {}...'.format(session['config']['email']['server']))
                smtpObj = smtplib.SMTP(session['config']['email']['server'], 25)
                # smtpObj.set_debuglevel(True)
                smtpObj.sendmail(sender, recipient, "\n".join(message))
                print("Successfully sent email to " + recipient + "...")
            except:
                print()
                mail_log_file_handle.write('Error sending mail to {}'.format(recipient))
                App.fail("Abort! Unable to send email...")

        # log
        for line in message:
            mail_log_file_handle.write(line)

        mail_log_file_handle.write("\n\n --- \n\n")

    # close log file
    mail_log_file_handle.close()

    i+=1

else:
    print('Not sending notifications...')

#################################################
# Clean up
#################################################
# remove the lock file
App.remove_lock()

# time script
sec = int(round(time.time()-start_time))
script_time = datetime.timedelta(seconds =sec)
print()
print('Script time:', script_time)
print()
print('Bye...')
