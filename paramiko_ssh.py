import paramiko
import os, sys, time
import string, pexpect, re
import subprocess
import logging, socket


# https://qxf2.com/blog/ssh-using-python-paramiko/
class paramkio_ssh:
    def __init__(self, host_name, user_name, password):
        self.ssh_output = None
        self.ssh_error = None
        self.client = None
        self.host = host_name
        self.username = user_name
        self.password = password
        self.timeout = 30
        # self.pkey = conf_file.PKEY
        self.port = 22
        # self.uploadremotefilepath = conf_file.UPLOADREMOTEFILEPATH
        # self.uploadlocalfilepath = conf_file.UPLOADLOCALFILEPATH
        # self.downloadremotefilepath = conf_file.DOWNLOADREMOTEFILEPATH
        # self.downloadlocalfilepath = conf_file.DOWNLOADLOCALFILEPATH

    def login(self):
        "Login to the remote server"
        try:
            # Paramiko.SSHClient can be used to make connections to the remote server and transfer files
            #print   "Establishing ssh connection"
            self.client = paramiko.SSHClient()
            # Parsing an instance of the AutoAddPolicy to set_missing_host_key_policy() changes it to allow any host.
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # Connect to the server
            if (self.password == ''):
                private_key = paramiko.RSAKey.from_private_key_file(self.pkey)
                self.client.connect(hostname=self.host, port=self.port, username=self.username, pkey=private_key,
                                    timeout=self.timeout, allow_agent=False, look_for_keys=False)
                #print    "Connected to the server", self.host
            else:
                self.client.connect(hostname=self.host, port=self.port, username=self.username, password=self.password,
                                    timeout=self.timeout, allow_agent=False, look_for_keys=False)
                #print   "Connected to the server", self.host
        except paramiko.AuthenticationException:
            print
            "Authentication failed, please verify your credentials"
            result_flag = False
        except paramiko.SSHException as sshException:
            print     "Could not establish SSH connection: %s" % sshException
            result_flag = False
        except socket.timeout as e:
            print       "Connection timed out"
            result_flag = False
        except Exception, e:
            print  "Exception in connecting to the server"
            print  "PYTHON SAYS:", e
            result_flag = False
            self.client.close()
        else:
            result_flag = True

        return result_flag

    def execute_command(self, command, **kargs):
        self.output = []
        result_flag = False
        timeout = self.timeout
        print("Command   :%s" % command)
        if "timeout" in kargs:
            timeout = kargs["timeout"]
        try:
            if self.login():
                stdin, stdout, stderr = self.client.exec_command(command, timeout)
                self.ssh_error = stderr.read()
                # #print stdout.read()
                self.output = stdout.read()
            if self.ssh_error:
                print "Problem occurred while running command:" + command + " The error is " + self.ssh_error
                result_flag = True
            else:
                print   "Command execution completed successfully", stdout.read()
                self.client.close()
        except socket.timeout as e:
            print        "Command timed out.", command
            self.client.close()
            result_flag = True
        except paramiko.SSHException:
            print        "Failed to execute the command!", command
            self.client.close()
            result_flag = True

        return result_flag






