#! /usr/bin/python3

####################################
# LIBRARIES
####################################
# parse cli arguments
import argparse
# caclulate a md5sum
import hashlib
# date, time
import datetime
# read the json file
import json
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
# http requests:
# $ apt install python3-urllib3
import urllib3
# yaml supprt
import yaml

# include 3d party libraries: add the lib/ dir to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))
# progress bar
from progress.bar import Bar
####################################
# MAIN VARIABLES
####################################
app_version = "2.0"
app_name = "hawkeye"
app_nickname = app_name + app_version.split('.')[0]

session_dir = os.path.dirname(__file__)
session_id = str(uuid.uuid4())
session_hash = hashlib.md5('.'.join(sys.argv[1:]).encode('utf-8')).hexdigest()
session_hostname = socket.gethostname()
####################################
# DATE AND TIME
####################################
date_stamp = str(datetime.datetime.now().date())
format = '%Y-%m-%d_%H%M%S'
datetime_stamp = str(datetime.datetime.now().strftime(format))

####################################
# PARSE ARGUMENTS
####################################
parser = argparse.ArgumentParser(description=app_name + app_version)
parser.add_argument('-s', '--servicesfile', help='Services json or yaml file', required=True)
parser.add_argument('-c', '--configfile', help='Config json or yaml file', required=False, default=os.path.join(session_dir, 'config/default.config.json'))
# flag without arguments
parser.add_argument('-v', '--verbose', help='verbose', required=False, default=False, action='store_true')
parser.add_argument('-m', '--monkey', help='mokey mode', required=False, default=False, action='store_true')
parser.add_argument('-t', '--tag', help='tag, e.g. server name', required=False, default=False)
args = parser.parse_args()

for services_log_file_path in [args.configfile, args.servicesfile]:
    if not os.path.isfile(services_log_file_path) and not os.path.islink(services_log_file_path):
        print('Abort! {} is not a file!'.format(services_log_file_path))
        exit(1)

####################################
# MONKEY
####################################
if args.monkey:
    monkey = True
else:
    monkey = False

####################################
# CONFIGURATION
####################################
cli_params = {}
cli_params['services'] = args.servicesfile
cli_params['config'] = args.configfile

cli_config = {}
for type, file_path in cli_params.items():
    if not os.path.isfile(file_path):
        print('{} file not found!'.format(type))
        exit(1)

    with open(file_path) as file:
        if re.search('.+\.json$', file_path):
            cli_config[type] = json.load(file)
        elif re.search('.+\.ya?ml$', file_path):
            cli_config[type] = yaml.load(file)
        else:
            print('{} file not supported!'.format(type))
            exit(1)

    # sort the files
    cli_config_tmp = {}
    keys = sorted(list(cli_config[type].keys()))
    for k in keys:
        cli_config_tmp[k] = cli_config[type][k]
    cli_config[type] = cli_config_tmp

# delete a random service
if monkey:
    services = list(cli_config['services'].keys())
    random_service =  random.choice(services)
    print()
    print('Monkey deleted service {} :)'.format(random_service))
    cli_config['services'].pop(random_service, None)

####################################
# VALIDATE APP CONFIG
####################################
for type in ['log', 'tmp']:
    try:
        dir = os.path.expanduser(cli_config['config']["dirs"][type])
    except:
        print('Abort! Directive dir:{} not set??'.format(type))
        exit(1)
    # use expanduser to deal with a tilda
    if os.path.isdir(dir) != True:
        print("Abort! {} dir {} not found!".format(type, dir))
        exit(1)

# set the variables
log_dir = os.path.normpath(os.path.expanduser(cli_config['config']["dirs"]["log"]))
tmp_dir = os.path.normpath(os.path.expanduser(cli_config['config']["dirs"]["tmp"]))

if not cli_config['config']['desktop']['trigger'] in ['warning', 'change']:
    print("Abort! Desktop trigger must be value warning|change")
    exit(1)

print()
print('{} {} ID {}'.format(app_name, app_version, session_id))
print()

####################################
# FUNCTIONS
####################################

# notifications for the desktop
def desktop_notify(messages):

    print()
    print('Notify desktop...')
    # for message in messages:
        # hyperlink_format = '<a href="{link}">{text}</a>'
        # print(hyperlink_format.format(link='http://foo/bar', text=message))

    # sudo apt install python3-notify2
    import notify2

    try:
        notify2.init(app_name + app_version)
        n = notify2.Notification(app_name.capitalize() + ' ' + app_version + ' warning', "\n".join(messages))
        n.show()
    except Exception as e:
        # the first one is usually the message.
        print('Could not notify desktop. Package python3-notify2 installed? {}'.format(e.args[1]))
        exit(1)

####################################
# ITERATE SERVICES
####################################
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings()

# create the http object
http = urllib3.PoolManager()

services_in_error = {}
services_to_notify_config = {}

number_of_services = len(cli_config['services'].items())

# create the progress bar
bar = Bar('Scanning...', max=number_of_services)

messages=[]
connectivity_checked = False
# request the urls
for service, service_config in cli_config['services'].items():

    # check connectivity
    if not connectivity_checked:
        connectivity_checked = True
        domain = service.split('//')[-1].split('/')[0].split('?')[0]
        try:
            # print('Connectivity check. Try {}... '.format(domain))
            resolved = socket.gethostbyname(domain)
        except OSError as e:
            print('Network connection failed! Cannot resolve {}. Error: "{}"...'.format(domain, e.args[1]))
            exit(1)

    # initiate status
    service_status = False

    # skip if tags do not match
    if args.tag and 'tag' in service_config:
        if args.tag != service_config['tag']:
            messages.append('Skipped ' + service + ' (tagged "' + service_config['tag'] + '")...')
            bar.next()
            continue

    # setup expected status
    if 'status' in service_config:
        status_expected = service_config['status']
    else:
        status_expected = 200

    if monkey:
        status_expected = random.randint(0,100)

    # check the response
    try:
        r = http.request('GET', service, timeout=float(cli_config['config']['request']['timeout']), retries=int(cli_config['config']['request']['retries']))
    except:
        services_in_error[service] = 'FAILED CONNECTION'

    if service not in services_in_error.keys():
        # add to error list if response does not match
        if r.status != status_expected:
            services_in_error[service] = 'FAILED RESPONSE ' + str(status_expected) + ' (' + str(r.status) + ')'
        # setup expected hash
        elif 'hash' in service_config:
            # $ wget https://some.url, $ cat index.html | md5sum
            hash_expected = service_config['hash']
            text = r.data.decode("utf-8")
            text_utf8 = text.encode("utf-8")
            md5_hash = hashlib.md5(text_utf8)
            hash_calculated = md5_hash.hexdigest()
            if hash_calculated != hash_expected:
                services_in_error[service] = 'FAILED MD5SUM ' + service_config['hash'] + ' (' + str(hash_calculated) + ')'

    # add the service to recipients needed to be notified
    for config in [service_config, cli_config['config']]:
        # setup notices
        if 'notify' in config:
            for recipient in config['notify']:
                # check if email already exists
                if not recipient in services_to_notify_config.keys():
                    services_to_notify_config[recipient] = []
                # add this service
                services_to_notify_config[recipient].append(service)

    bar.next()
bar.finish()

# print messages
if len(messages):
    print()
    for m in messages:
        print(m)

print()
####################################
# SERVICES TMP AND LOG FILES
####################################
services_tmp_file_path = os.path.join(tmp_dir, app_nickname + '.' + session_hash + '.' + datetime_stamp + '.' + session_id + '.services.tmp')
services_tmp_file = open(services_tmp_file_path, 'w')

services_log_file_path = os.path.join(log_dir, app_nickname + '.' + date_stamp + '.services.log')
# status_log_file_path = os.path.join(log_dir, script_name + '.status.log')
print('Write log file... {}'.format(services_log_file_path))
services_log_file = open(services_log_file_path, 'a')

# iterate through all services
for service, service_config in cli_config['services'].items():
    if service in services_in_error:
        new_status = services_in_error[service]
    else:
        new_status = 'OK'

    line = datetime_stamp + ';' + session_id + ';' + service + ';' + new_status + "\n"
    services_tmp_file.write(line)
    services_log_file.write(line)

# close files
services_tmp_file.close()
services_log_file.close()
####################################
# STATUS LOG FILE
####################################
# print final status
if len(services_in_error) == 0:
    global_status = 'OK!'
else:
    global_status = 'WARNING'

print()
print('SERVICES {}!'.format(global_status))

messages = []
if global_status == "WARNING":
    print()
    for service, status in services_in_error.items():
        messages.append("\t{} {}".format(service, status))

    for message in messages:
        print(message)
    #
    # if config['desktop']['enabled']:
    #     if config['desktop']['trigger'] == 'warning':
    #         desktop_notify(messages)

print()

####################################
# STORE STATUSES
####################################
# get a list of all files in tmp dir
tmp_files = os.listdir(tmp_dir)

# add all the service tmp files to a list
service_tmp_files = []
for file in tmp_files:
    if re.search(app_nickname + '.' + session_hash + '.+\.services\.tmp$', file):
        service_tmp_files.append(file)

service_tmp_files.sort(reverse=True)

# just keep the 2 last files for comparison
if not re.match('^/tmp/?$', tmp_dir):
    i=2
    while i < len(service_tmp_files):
        shutil.move(os.path.join(tmp_dir, service_tmp_files[i]), '/tmp')
        i += 1

changes = {}
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
        service_log_file = open(service_log_file_path, 'r')

        # store the contents of the files in a list
        service_log_lines = service_log_file.readlines()

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

    ####################################
    # COMPARE THE STATUSES
    ####################################
    for service, new_status in service_status_log['new'].items():
        # do not compare a new service
        if not service in service_status_log['old']:
            changes[service] = new_status
            print('New service detected... {}'.format(service))
        elif not service_status_log['new'][service] == service_status_log['old'][service]:
            changes[service] = new_status
            print('Change in service detected... {}'.format(service))

if len(changes) == 0:
    print('No changes, no notifications...')

####################################
# DESKTOP ALERT
####################################
notify_desktop = False
if config['desktop']['enabled']:
    if config['desktop']['trigger'] == 'change':
        if len(changes) != 0:
            notify_desktop = True
    # contiuous notifications
    else:
        if global_status == 'WARNING':
            notify_desktop = True

if notify_desktop:
    desktop_notify(messages)

####################################
# COMPILE LIST OF EMAIL RECIPIENTS
####################################
notify_email = False
if config['email']['enabled']:
    if len(changes) != 0:
        notify_email = True

# log mails - purely for debugging - /tmp used
mail_log_file_path = os.path.join('/tmp', app_nickname + '.' + session_hash + '.' + datetime_stamp + '.' + session_id + '.mail.log')
mail_log_file = open(mail_log_file_path, 'a')

# send messages
if notify_email:
    print()
    recipients_to_notify = []
    # messages
    for service, status in changes.items():
        # default notifications
        for email_address in cli_config['config']['notify']:
            if email_address not in recipients_to_notify:
                recipients_to_notify.append(email_address)
            # create a list if required
            # if recipient not in messages.keys():
            #     messages[recipient] = []
            # messages[recipient].append(service + ' : ' + status)

        # extra notifications per service
        if 'notify' in cli_config['services'][service].keys():
            for email_address in cli_config['services'][service]['notify']:
                if email_address not in recipients_to_notify:
                    recipients_to_notify.append(email_address)

    # no recipients
    if len(recipients_to_notify) == 0:
        print('No recipients found...')
        print()
        exit()

    ####################################
    # PREPARE MAILS
    ####################################
    # no mail config - allow tmp files to be created!!
    if not cli_config['config']['email']['enabled'] == True:
        print('Email not enabled...')
        print()
        exit()

    mails = {}
    for recipient in recipients_to_notify:
        mails[recipient] = {}
        warnings = 0
        body = []
        # iterate all service_notices
        for service_to_notify in services_to_notify_config[recipient]:
            if service_to_notify in services_in_error.keys():
                warnings += 1
                indent = "\t\t"
                newline = '' # '"\n"
            else:
                indent = ''
                newline = ''

            # append all services to body
            body.append(newline + indent + service_to_notify + " " + service_status_log['new'][service_to_notify] + newline)

        if warnings:
            status = str(warnings) + ' SERVICE(S) FAILED!'
        else:
            status = 'SERVICES OK'

        subject = app_nickname.upper() + ' @' + session_hostname + ' ' + status

        mails[recipient]['subject'] = subject
        mails[recipient]['body'] = body

    ####################################
    # SEND MAILS
    ####################################
    # iterate all mails
    fqdn = socket.getfqdn()
    for recipient in mails.keys():

        sender = app_nickname + '@' + fqdn

        message = []
        message.append('From: <' + sender + '>')
        message.append('To: <' + recipient + '>')
        message.append('Subject: ' + mails[recipient]['subject'])
        # newline between subject and message?
        message.append('')
        for line in mails[recipient]['body']:
            message.append(line)

        message.append('')
        message.append('Run ID: {}'.format(session_id))

        if args.verbose:
            print("\n".join(message))

        try:
            print('Sending mails to server {}...'.format(cli_config['config']['email']['server']))
            smtpObj = smtplib.SMTP(cli_config['config']['email']['server'], 25)
            # smtpObj.set_debuglevel(True)
            smtpObj.sendmail(sender, recipient, "\n".join(message))
            print("Successfully sent email to " + recipient + "...")
        except:
            print()
            print("Error! Unable to send email...")
            mail_log_file.write('ERROR sending mail to {}'.format(recipient))
            exit(1)

        # log
        for line in message:
            mail_log_file.write(line)

        mail_log_file.write("\n\n --- \n\n")

    # close log file
    mail_log_file.close()

    print()

print('Bye...')
