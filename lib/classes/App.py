#! /usr/bin/env python3

import os

class App:

    lockfile = ''

    lockfile_max_age = 3600 # timeout in seconds: 1 hr = 3600 secs

    name = 'hawkeye'

    version = '2.4'

    full_version = '' # will be set in class initiation

    def __init__(self, session_hash):

        self.PID = str(os.getpid())

        self.lockfile = "/tmp/{}.{}.lock".format(self.name, session_hash)

        git_commits = os.popen('cd ' + os.path.dirname(os.path.abspath(__file__)) + '; git rev-list HEAD | wc -l 2>/dev/null;').read().rstrip()
        git_hash = os.popen('cd ' + os.path.dirname(os.path.abspath(__file__)) + '; git rev-parse --short HEAD 2>/dev/null;').read().rstrip()
        self.full_version = '{}.{}.{}'.format(self.version, git_commits, git_hash)


    def file_age_in_seconds(self, pathname):
        """ Get the age of a file in seconds. """
        return time.time() - os.stat(pathname)[stat.ST_MTIME]


    def check_pid_is_running(self, pid):
        """ Check For the existence of a unix pid. """
        try:
            os.kill(int(pid), 0)
        except OSError:
            return False
        else:
            return True

    def init_lock(self):
        """ Check lock file and create if required. """
        # it exists, check if there is a process running with that ID
        if os.path.isfile(self.lockfile):

            # check PID in lockfile and check if it is running
            with open(self.lockfile, 'r') as file:
                data = file.read().replace('\n', '')
            lockfile_pid = data.strip()

            if lockfile_pid != '':
                # print('Pid lockfile:' + lockfile_pid)

                # check if process is still running
                if self.check_pid_is_running(lockfile_pid):
                    # check if lockfile is old
                    lockfile_age = float(self.file_age_in_seconds(self.lockfile))
                    # print('Age: {}, Max: {}'.format(lockfile_age, self.lockfile_max_age))
                    if lockfile_age < self.lockfile_max_age:
                        print('Abort, lock file exists! {}'.format(self.lockfile))
                        exit(1) # do not call the quit() function. The lock file is there for a purpose!

        # if we got this far, create it
        file = open(self.lockfile, "w")
        # print(PID)
        file.write(self.PID)
        file.close()

    def remove_lock(self):
        """ Clean up, remove lock file. """
        if os.path.isfile(self.lockfile):
            os.remove(self.lockfile)

    def fail(self, message = ''):
        """ Fail, exit with non-zero. """
        if message != '':
            print(message)

        self.quit(1)

    def quit(self, error_code = 0, remove_lock = True):
        """ End the application. """
        if remove_lock:
            self.remove_lock()

        exit(error_code)