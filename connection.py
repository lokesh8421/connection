import sys
import time, string, pexpect, re
import subprocess
import logging

class Connection:
    def __init__(self, host_name, user_name, password, connection_type):
        self.hostname = host_name
        self.username = user_name
        self.password = password
        self.log = None
        self.timeout = 30
        self.protocol = connection_type
        self.force_wait = 0
        self.prompt = "[^#]#[ ]*$"
        self._login = False
        self._log = None
        self.s = None
        self.verify = False
        self.port = None
        self._term_len = 0  # terminal length for cisco devices
        self.searchwindowsize = 10000
        self._login = False  # set to true at first successful login
        self.output = ""  # output from last command

    def __connected(self):
        # determine if a connection is already open
        connected = (self.s is not None and self.s.isatty())
        logging.debug("check for valid connection: %r" % connected)
        return connected

    @property
    def term_len(self): return self._term_len

    @term_len.setter
    def term_len(self, term_len):
        self._term_len = int(term_len)
        if (not self.__connected()) or (not self._login):
            # login function will set the terminal length
            self.login()
        else:
            # user changing terminal length during operation, need to explicitly
            self.cmd("terminal length %s" % self._term_len)

    def start_log(self):
        """ start or restart sending output to logfile """
        if self.log is not None and self._log is None:
            # if self.log is a string, then attempt to open file pointer (do not catch exception, we want it
            # to die if there's an error opening the logfile)
            if isinstance(self.log, str) or isinstance(self.log, unicode):
                self._log = file(self.log, "a")
            else:
                self._log = self.log
            logging.debug("setting logfile to %s" % self._log.name)
            if self.child is not None:
                self.child.logfile = self._log

    def stop_log(self):
        """ stop sending output to logfile """
        self.child.logfile = None
        self._log = None
        return

    def connect(self):
        # close any currently open connections
        #self.close()

        # determine port if not explicitly set
        if self.port is None:
            if self.protocol == "ssh":
                self.port = 22
            if self.protocol == "telnet":
                self.port = 23
        # spawn new thread
        if self.protocol.lower() == "ssh":
            logging.debug("spawning new pexpect connection: ssh %s@%s -p %d" % (self.username, self.hostname, self.port))
            no_verify = " -o StrictHostKeyChecking=no -o LogLevel=ERROR -o UserKnownHostsFile=/dev/null"
            if self.verify: no_verify = ""
            self.child = pexpect.spawn("ssh %s %s@%s -p %d" % (no_verify, self.username, self.hostname, self.port),
                searchwindowsize = self.searchwindowsize)
            self.child.setwinsize(1000,1000)
        elif self.protocol.lower() == "telnet":
            logging.info("spawning new pexpect connection: telnet %s %d" % (self.hostname, self.port))
            self.child = pexpect.spawn("telnet %s %d" % (self.hostname, self.port),
                searchwindowsize = self.searchwindowsize)
            self.child.setwinsize(1000, 1000)
        else:
            logging.error("unknown protocol %s" % self.protocol)
            raise Exception("Unsupported protocol: %s" % self.protocol)

        # start logging
        self.start_log()

    def close(self):
        # try to gracefully close the connection if opened
        if self.__connected():
            logging.info("closing current connection")
            self.child.close()
        self.child = None
        self._login = False

    def __expect(self, matches, timeout=None):
        """
        receives a dictionary 'matches' and returns the name of the matched item
        instead of relying on the index into a list of matches.  Automatically
        adds following options if not already present
            "eof"       : pexpect.EOF
            "timeout"   : pexpect.TIMEOUT
        """

        if "eof" not in matches:
            matches["eof"] = pexpect.EOF
        if "timeout" not in matches:
            matches["timeout"] = pexpect.TIMEOUT

        if timeout is None: timeout = self.timeout
        indexed = []
        mapping = []
        for i in matches:
            indexed.append(matches[i])
            mapping.append(i)
        result = self.child.expect(indexed, timeout)
        logging.debug("timeout: %d, matched: '%s'\npexpect output: '%s%s'" % (
            timeout, self.child.after, self.child.before, self.child.after))
        if result <= len(mapping) and result>=0:
            logging.debug("expect matched result[%d] = %s" % (result, mapping[result]))
            return mapping[result]
        ds = ''
        logging.error("unexpected pexpect return index: %s" % result)
        for i in range(0,len(mapping)):
            ds+= '[%d] %s\n' % (i, mapping[i])
        logging.debug("mapping:\n%s" % ds)
        raise Exception("Unexpected pexpect return index: %s" % result)

    def login(self):
        """
        returns true on successful login, else returns false
        """

        logging.debug("Logging into host")

        # successfully logged in at a different time
        if not self.__connected(): self.connect()
        # check for user provided 'prompt' which indicates successful login
        # else provide approriate username/password/enable_password
        max_attempts = 7  # console, yes/no, username, password, enable + buffer
        matches = {
            "console"   : "(?i)press return to get started",
            "refuse"    : "(?i)connection refused",
            "yes/no"    : "(?i)yes/no",
            "username"  : "(?i)(user(name)*|login)[ as]*[ \t]*:[ \t]*$",
            "password"  : "(?i)password[ \t]*:[ \t]*$",
            "enable"    : ">[ \t]*$",
            "prompt"    : self.prompt
        }

        last_match = None
        while max_attempts>0:
            max_attempts-=1
            match = self.__expect(matches, 17)
            if match == "console":      # press return to get started
                logging.debug("matched console, send enter")
                self.child.sendline("\r\n")
            elif match == "refuse":    # connection refused
                logging.error("connection refused by host")
                return False
            elif match == "yes/no":   # yes/no for SSH key acceptance
                logging.debug("received yes/no prompt, send yes")
                self.child.sendline("yes")
            elif match == "username":   # username/login prompt
                logging.debug("received username prompt, send username")
                self.child.sendline(self.username)
            elif match == "password":
                # don't log passwords to the logfile
                self.stop_log()
                if last_match == "enable":
                    # if last match was enable prompt, then send enable password
                    logging.debug("matched password prompt, send enable password")
                    self.child.sendline(self.enable_password)
                else:
                    logging.debug("matched password prompt, send password")
                    self.child.sendline(self.password)
                # restart logging
                self.start_log()
            elif match == "enable":
                logging.debug("matched enable prompt, send enable")
                self.child.sendline("enable")
            elif match == "prompt":
                logging.debug("successful login")
                self._login = True
                # force terminal length at login
                self.term_len = self._term_len
                return True
            elif match == "timeout":
                logging.debug("timeout received but connection still opened, send enter")
                self.child.sendline("\r\n")
            last_match = match
        # did not find prompt within max attempts, failed login
        logging.error("failed to login after multiple attempts")
        return False

    def run_command(self, command, **kargs):
        """
        execute a command on a device and wait for one of the provided matches to return.
        Required argument string command
        Optional arguments:
            timeout - seconds to wait for command to completed (default to self.timeout)
            sendline - boolean flag to use send or sendline fuction (default to true)
            matches - dictionary of key/regex to match against.  Key corresponding to matched
                regex will be returned.  By default, the following three keys/regex are applied:
                    'eof'       : pexpect.EOF
                    'timeout'   : pexpect.TIMEOUT
                    'prompt'    : self.prompt
            echo_cmd - boolean flag to echo commands sent (default to false)
                note most terminals (i.e., Cisco devices) will echo back all typed characters
                by default.  Therefore, enabling echo_cmd may cause duplicate cmd characters
        Return:
        returns the key from the matched regex.  For most scenarios, this will be 'prompt'.  The output
        from the command can be collected from self.output variable
        """

        sendline = True
        timeout = self.timeout
        matches = {}
        echo_cmd = False
        if "timeout" in kargs:
            timeout = kargs["timeout"]
        if "matches" in kargs:
            matches = kargs["matches"]
        if "sendline" in kargs:
            sendline = kargs["sendline"]
        if "echo_cmd" in kargs:
            echo_cmd = kargs["echo_cmd"]

        # ensure prompt is in the matches list
        if "prompt" not in matches:
            matches["prompt"] = self.prompt

        self.output = ""
        # check if we've ever logged into device or currently connected
        if (not self.__connected()) or (not self._login):
            logging.debug("no active connection, attempt to login")
            if not self.login():
                raise Exception("failed to login to host")

        # if echo_cmd is disabled, then need to disable logging before
        # executing commands
        if not echo_cmd: self.stop_log()

        # execute command
        logging.debug("cmd command: %s" % command)
        if sendline: self.child.sendline(command)
        else: self.child.send(command)

        # remember to re-enable logging
        if not echo_cmd: self.start_log()

        # force wait option
        if self.force_wait != 0:
            time.sleep(self.force_wait)
        print("Command   :%s" % command)
        result = self.__expect(matches, timeout)
        #print("Man1 %s",self.child.before )
        #print("Man2 %s", self.child.after)
        #self.output = "%s%s" % (self.child.before, self.child.after)
        self.output = "%s%s" % (self.child.before, self.child.after)
        keep_list = []
        for line in str.splitlines(self.output):
              if line not in command:
                  if (line.find("ps=1") == -1):
                      keep_list.append(line)

        #result = keep_list[-2]
        keep_list = keep_list[:len(keep_list) - 2]
        self.output = []
        self.output = "\n".join(line.strip() for line in keep_list)
        #result  = re.search("(0)", result)
        #result  = re.search(r'\((.*)\)', result)
        #print(result.group(0))
        if sendline:
            self.child.sendline("echo RESULT:$?")
        else:
            self.child.sendline("echo RESULT:$?")
        result = self.__expect(matches, timeout)
        result = re.search("RESULT:0", self.child.before)
        if result:
            return 0;
        else:
            return 255;
        #return result

    def copyFilesToDest(self, hostfile, destip, destuser, destPath, passwd):
        # cmd = ("/usr/bin/scp "+ " -v " + \
        #    " -o"," UserKnownHostsFile=/dev/null "+ \
        #   " -o"," StrictHostKeyChecking=no "+ \
        #    hostfile+\
        #    " {}@{}:{}".format(destuser,destip,destPath))
        timeout = 50000
        cmd = "scp -r -o StrictHostKeyChecking=no {} {}@{}:{}".format(hostfile, destuser, destip, destPath)
        obj = pexpect.spawn(cmd)

        obj.logfile = sys.stdout
        obj.expect('assword: ')
        obj.sendline(passwd)
        obj.expect('#', timeout)
        #obj.expect(pexpect.EOF)
        obj.close()


