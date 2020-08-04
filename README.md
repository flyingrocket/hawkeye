# README #
### Copyright ###
Hawkeye

Copyright (C) 2015 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by Bruno Dooms, see <https://github.com/flyingrocket/hawkeye.git>.

### Summary ###
* Quick summary: Hawkeye - monitoring script for urls
* Version: Hawkeye version 2.0

### Install ###
Python 3 must be installed.

Install python packages in Ubuntu or Debian:

    apt install python3-urllib3 python3-yaml python3-requests

Install this package on a Desktop:

    apt install python3-notify2

### Usage ###

    -h, --help            show this help message and exit
    -s SERVICESFILE, --servicesfile SERVICESFILE
                        Services json or yaml file
    -c CONFIGFILE, --configfile CONFIGFILE
                        Config json or yaml file
    -v, --verbose         verbose
    -m, --monkey          mokey mode
    -d, --debugmode       debug mode
    -t TAG, --tag TAG     tag, e.g. server name

### Example ###

    /home/kermit/bin/hawkeye2/hawkeye.py -c /home/kermit/hawkeye2.d/config/muppets.config.yaml -s /home/kermit/hawkeye2.d/config/muppets.services.yaml
