#!/usr/bin/python
# -*- coding: utf-8 -*-
#################################################
#              Snort Alert Log Reader           #
#            author: Dmitry Nikolaenya          #
#            https://github.com/goooroooX       #
#               https://gooorooo.com            #
#################################################

# Copyright 2017 Dmitry Nikolaenya
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Crontab settings to run each 2 hours:
# chmod +x /opt/snort_reader/snort_alert_reader.py
# 0 */2 * * * /opt/snort_reader/snort_alert_reader.py > /dev/null 2>&1
# ps auwwwx | grep snort_alert_reader

VERSION = "1.6"
RELEASE = "20171214"
NOTES = """
20170714: initial code base
20170816: alert log processing
20170817: rotation handling and notifications
20170818: last message from notification queue sending
20171013: minor fixes
20171018: notification sender fixed
20171207: alert file rotation infinite loop, email notifications
20171214: fix to previous update
"""

VERBOSE_DEBUG = False

import os, sys
import time
import traceback
import logging
from logging.handlers import RotatingFileHandler
import signal
import atexit
import ConfigParser
import json
import re
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

if getattr(sys, 'frozen', False):
    root_folder = os.path.dirname(os.path.abspath(sys.executable))
else:
    root_folder = os.path.dirname(os.path.abspath(__file__))

libs_folder = os.path.join(root_folder, 'lib')
if os.path.isdir(libs_folder):
    sys.path.append(libs_folder)
    if os.path.isdir(libs_folder):
        sys.path.append(libs_folder)
        for zipped in os.listdir(libs_folder):
            extension = os.path.splitext(zipped)[1]
            if extension in [".egg", ".whl", ".zip"]:
                sys.path.append('%s/%s' % (libs_folder, zipped))

# setup logger
def my_logger(LOG_FILENAME):
    FORMAT_FILE = '%(asctime)-15s %(levelname)-8s : %(message)s'
    FORMAT_CLI  = '%(asctime)-8s %(levelname)-8s %(message)s'
    MAX_BYTES = 3*1024*1024
    BACKUP_COUNT = 10
    logger = logging.getLogger()
    # logging to file
    fileFormatter = logging.Formatter(FORMAT_FILE)
    fileHandler = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT)
    fileHandler.setLevel(logging.DEBUG)
    fileHandler.setFormatter(fileFormatter)
    logger.addHandler(fileHandler)
    # logging to console
    consoleFormatter = logging.Formatter(FORMAT_CLI, '%H:%M:%S')
    consoleHandler = logging.StreamHandler()
    consoleHandler.setLevel(logging.INFO)
    consoleHandler.setFormatter(consoleFormatter)
    logger.addHandler(consoleHandler)
    logger.setLevel(logging.DEBUG)
    return logger

LOG_NAME = "alert_snort_reader.log"
log = my_logger(os.path.join("/var/log", LOG_NAME))
is_linux = os.name == 'posix'

def check_pid():
    pid_file = "reader.pid"
    need_start = False
    # write pid file
    def write_pid(pid_name, pid_value):
        pid_file = open(pid_name, "wb")
        pid_file.write(str(pid_value))
        pid_file.close()
    # check pid
    def pid_exists(pid):
        if is_linux:
            import errno
            if pid < 0:
                return False
            try:
                os.kill(pid, 0)
            except OSError as e:
                return e.errno == errno.EPERM
            else:
                return True
        else:
            import ctypes
            import ctypes.wintypes
            _STILL_ACTIVE = 259
            PROCESS_QUERY_INFROMATION = 0x1000
            processHandle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFROMATION, 0, pid)
            if processHandle == 0:
                return False
            # if the process exited recently, a pid may still exist for the handle
            # so, check if we can get the exit code
            exit_code = ctypes.wintypes.DWORD()
            is_running = (ctypes.windll.kernel32.GetExitCodeProcess(processHandle, ctypes.byref(exit_code)) == 0)
            ctypes.windll.kernel32.CloseHandle(processHandle)
            return is_running or exit_code.value == _STILL_ACTIVE

    # check if we are running
    pid_new = int(os.getpid())
    pid_name = os.path.join(root_folder, pid_file)
    if os.path.isfile(pid_name):
        pid_file = open(pid_name, "rb")
        try:
            pid_old = int(pid_file.readline())
            pid_file.close()
        except:
            print("Invalid pid representation, cleaning up...")
            pid_file.close()
            os.remove(pid_name)
            need_start = True
        else:
            if pid_exists(pid_old):
                print("One instance (pid %s) already running, initialization cancelled." % pid_old)
            else:
                print("Process found dead, initializing...")
                os.remove(pid_name)
                need_start = True
    else:
        print("Process not running, initializing...")
        need_start = True
    if need_start:
        write_pid(pid_name, pid_new)
    return need_start, pid_new

need_start, my_pid = check_pid()
if not need_start:
    print("Process already running, ending current process with pid %s" % my_pid)
    sys.exit(0)
else:
    log.info("Process started with pid %s" % str(my_pid))

class SIGException(Exception):
    pass

def set_signals():
    def sig_handler(signum = None, frame = None):
        log.warning("SIG handler called with signal: %s." % signum)
        raise SIGException()
    if is_linux:
        sigset = [signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT]
        log.debug("Enabling signals handler for: POSIX")
    else:
        sigset = [signal.SIGTERM, signal.SIGINT, signal.SIGABRT, signal.SIGBREAK]
        log.debug("Enabling signals handler for: WINDOWS")
    for sig in sigset:
        signal.signal(sig, sig_handler)

def exit_handler():
    log.info("***************************************************************")
    log.info("******************* SNORT READER FINALIZED ********************")
    log.info("***************************************************************")

class Config():

    def __init__(self, conf_path):
        self.conf = None
        config_parser = ConfigParser.SafeConfigParser()
        try:
            cfg = os.path.join(root_folder, conf_path)
            if not os.path.isfile(cfg):
                log.error("Failed to open config file: %s" % cfg)
            else:
                config_parser.readfp(open(cfg))
                conf = {}
                for section in config_parser.sections():
                    conf[section] = {}
                    if section == 'main':
                        try:
                            self.alert_log_path = config_parser.get(section, 'snort_log')
                        except:
                            log.error("Snort alert log file location not defined in configuration! Exiting.")
                            sys.exit(1)
                        try:
                            self.notify_cmd     = config_parser.get(section, 'notify_cmd')
                        except:
                            log.warning("Notification script not defined in configuration. Scripted notifications disabled.")
                            self.notify_cmd = None
                        try:
                            self.notify_email   = config_parser.get(section, 'notify_email')
                        except:
                            log.warning("Notification email not defined in configuration. Email notifications disabled.")
                            self.notify_email = None
                self.conf = conf
                log.debug("Configuration file OK.")
        except:
            log.error("Failed to process configuration file: %s" % traceback.format_exc())

    def get_log_path(self):
        return self.alert_log_path

    def get_notify_cmd(self):
        return self.notify_cmd
        
    def get_notify_email(self):
        return self.notify_email

class LogReader():

    def __init__(self, conf):

        self.log_path       = None
        self.notify_cmd     = None
        self.notify_email   = None
        self.saved          = False
        self.loaded         = False
        self.save_time      = None
        self.position       = 0
        self.save_file_name     = os.path.join(root_folder, "position.save")
        self.notify_file_name   = os.path.join(root_folder, "notify.save")
        self.active_log_object  = None
        self.pattern            = re.compile("^(\d+/\d+-\d+:\d+:\d+).+?\]\s+\[([\d:]+)\]\s+(.+?)\s+\[.+?Classification:\s+(.+?)\].+?Priority:\s+(\d+)\]\s+\{(.+?)\}\s+(\d+\.\d+\.\d+\.\d+):?(\d+)?\s+->\s+(\d+\.\d+\.\d+\.\d+):?(\d+)?")
        self.check_interval     = 30
        self.idle_processed     = 0
        self.notification_pool  = []
        self.notify_hours       = 6
        self.reload_zero_hours  = 3

        # check log path
        log_path = conf.get_log_path()
        if not os.path.isfile(log_path):
            log.error("Input file not found: %s" % log_path)
        else:
            try:
                with open(log_path) as fp:
                    fp.close()
            except IOError as err:
                log.error("Error reading the file {0}: {1}".format(log_path, err))
            else:
                self.log_path = log_path

        # check notification email
        notify_email = conf.get_notify_email()
        if notify_email:
            if not "@" in notify_email:
                log.warning("Incorrect notification email : '%s'. Email notifications are disabled." % notify_email)
            else:
                log.info("Email notifications are enabled for address: %s" % notify_email)
                self.notify_email = notify_email
        else:
            log.info("Notification email is disabled in configuration.")

        # check notification script
        notify_cmd = conf.get_notify_cmd()
        if notify_cmd:
            if not os.path.isfile(notify_cmd):
                log.warning("Notification script not found: '%s'. External notifications are disabled." % notify_cmd)
            else:
                log.info("Scripted notifications are enabled: %s" % notify_cmd)
                self.notify_cmd = notify_cmd
        else:
            log.info("Notification script is disabled in configuration.")

    def get_log_path(self):
        return self.log_path

    def load_state(self):
        log.info("Loading last collect state...")
        if not os.path.isfile(self.save_file_name):
            log.info("Save file not exists, starting from 0")
            self.position = 0
            self.loaded = False
            return True
        try:
            file = open(self.save_file_name, "rb")
        except:
            log.error("Failed to open save file: %s" % self.save_file_name)
            return False
        try:
            data = json.load(file)
        except:
            log.error("Failed lo load JSON data from file: %s" % self.save_file_name)
            return False

        file.close()
        self.position  = data["position"]
        self.save_time = int(data["save_time"])

        # check if last collect was long time ago (more than 24 hours)
        if int(time.time()) - self.save_time > 24*60*60:
            log.warning("Last collect time more than 24 hours ago. Restarting from 0.")
            self.position = 0

        self.loaded = True
        return True

    def save_state(self):
        self.saved      = False
        self.save_time  = int(time.time())
        try:
            file = open(self.save_file_name, "wb")
        except:
            log.error("Failed to write save file: %s" % self.save_file_name)
            return False

        json_object = {
            "position":  self.position,
            "save_time": self.save_time
        }
        dump = json.dumps(json_object, indent=4, separators=(',', ':'))

        file.write(dump)
        file.close()
        self.saved = True
        log.debug("Save file updated.")
        return True

    def open_active_log(self):
        try:
            self.active_log_object = open(self.log_path, 'r')
            return True
        except:
            log.error("Failed to open file for reading: '%s'" % self.log_path)
            return False

    def check_rotation(self):
        try:
            curr_size = os.path.getsize(self.log_path)
            if curr_size < self.position:
                return True
            else:
                return False
        except:
            log.error("Log file not found when checking rotation! Exiting.")
            sys.exit(1)

    def notify_check(self, message = None):
        notify_me = False
        curr_time = int(time.time())
        if os.path.isfile(self.notify_file_name):
            try:
                file_r = open(self.notify_file_name, "rb")
                data = file_r.read()
                file_r.close()
            except:
                log.error("Failed lo load notification last time from file: %s" % self.notify_file_name)
                log.info("Disabling notifications.")
                self.notify_cmd   = None
                self.notify_email = None
            else:
                try:
                    last_time = int(data)
                except:
                    log.error("Bad notification last time format: %s" % data)
                    os.remove(self.notify_file_name)
                else:
                    if curr_time > last_time + self.notify_hours * 60 * 60:
                        notify_me = True
                    else:
                        if message:
                            self.notification_pool.append(message)
        else:
            notify_me = True
        return notify_me

    def notify_save(self):
        if os.path.isfile(self.notify_file_name):
            curr_time = int(time.time())
        else:
            curr_time = int(time.time() - 1)
        try:
            file_w = open(self.notify_file_name, "wb")
            file_w.write(str(curr_time))
            file_w.close()
        except:
            log.error("Failed to write notification last time file: %s" % self.notify_file_name)
            log.info("Disabling notifications.")
            self.notify_cmd   = None
            self.notify_email = None
        log.debug("Notification file updated.")

    def notify(self, *arg):
        if self.notify_cmd or self.notify_email:
            from_queue = False
            if not arg:
                if len(self.notification_pool) > 0:
                    message = self.notification_pool[-1]
                    from_queue = True
                else:
                    log.error("No notification message provided, and queue is empty!")
                    return
            else:
                message = "\"" + "SNORT ALERT" + "\""
                for entry in arg:
                    message = message + " " + "\"" + entry + "\""
            
            log.info('Notification requested: %s' % message)
            if from_queue:
                log.info("This is the last notification from queue.")

            # check if we need to get notification, one run per 6 hours
            notify_me = self.notify_check(message)

            queue = len(self.notification_pool)
            if not notify_me and queue > 0:
                log.info("%s hours not yet passed, now %s messages in notification queue." % (self.notify_hours, queue))
            elif not notify_me and queue == 0:
                log.info("Notification will NOT be send!")
            elif notify_me:
                if queue > 0:
                    message = message + " \"" + "MESSAGE POOL: %s" % queue + "\""
                    self.notification_pool = []
                if from_queue:
                    message = message + " \"" + "NOTE: this is the last message from queue" + "\""
                if self.notify_cmd:
                    os.system('%s %s' % (self.notify_cmd, message))
                    log.info("Notification script executed.")
                if self.notify_email:
                    message = message.replace("\" \"", "\n")
                    message = message.replace("\"", "")
                    self.send_email(message)

                # save the last notification time
                self.notify_save()

    def send_email(self, message):
        if is_linux:
            message = message.replace('\n', '<br>')
            email_body = '<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"/></head><body><br>%s<br></body></html>' % message
            sender      = "alert@snortreader"
            recipient   = self.notify_email
            smtp_server = None
            smtp_port   = None
            smtp_user   = None
            smtp_pass   = None
            
            # read /etc/mail.rc for email server details
            
            #set smtp=smtp://smtp.server.com:25
            #set smtp-auth=login
            #set smtp-auth-user=username1
            #set smtp-auth-password=password2
            #set ssl-verify=ignore
            
            mail_config = "/etc/mail.rc"
            if os.path.isfile(mail_config):
                try:
                    f = open(mail_config, "r")
                    for line in f:
                        match_server = re.findall("set smtp=smtp://(.+?):(\d+)", line)
                        if match_server:
                            smtp_server = match_server[0][0]
                            smtp_port   = match_server[0][1]
                        match_user = re.findall("set smtp-auth-user=(.+?)\s*$", line)
                        if match_user:
                            smtp_user = match_user[0]
                        match_pass = re.findall("set smtp-auth-password=(.+?)\s*$", line)
                        if match_pass:
                            smtp_pass = match_pass[0]
                    log.debug("Sending to %s:%s as %s/%s" % (smtp_server, smtp_port, smtp_user, "********"))
                except:
                    log.error("Failed to read %s" % mail_config)
            
            if not smtp_server:
                smtp_server = "127.0.0.1"

            # prepare email
            msg = MIMEMultipart('alternative')
            msg['Subject']  = "Snort Alert"
            msg['From']     = sender
            msg['To']       = recipient
            part1 = MIMEText(email_body.encode('utf8'), 'plain', 'utf-8')
            part2 = MIMEText(email_body.encode('utf8'), 'html',  'utf-8')
            msg.attach(part1)
            msg.attach(part2)
            try:
                s = smtplib.SMTP(smtp_server, int(smtp_port))
                if smtp_user and smtp_pass:
                    s.login(smtp_user, smtp_pass)
                s.sendmail(sender, recipient, msg.as_string())
                s.quit()
                log.info("Email sent OK.")
            except:
                log.error("Failed to send email: %s" % traceback.format_exc())
        else:
            log.warning("Email sending is not implemented for non-Linux platforms.")

    def start_tail(self):

        if not self.load_state():
            return False

        if not self.loaded:
            self.save_state()

        if not self.open_active_log():
            return False

        if self.position > 0:
            log.info("Continue collect from position: %s" % self.position)
            try:
                self.active_log_object.seek(self.position)
            except:
                log.error("Failed to seek position, file probably changed.")
                log.info("Moving to the start of the file...")
                self.active_log_object.seek(0)
        else:
            log.info("Starting monitoring from position 0.")

        idle_time_start = None
        zero_size_start = None
        
        log.info("Log file monitor started: %s" % self.get_log_path())
        
        while True:
            line = self.active_log_object.readline().strip()

            # pause collection when nothing to read
            if not line:
                if not idle_time_start:
                    idle_time_start = int(time.time())

                # TODO: flush database

                # check if file have rotated
                self.idle_time = int(time.time()) - idle_time_start
                if self.idle_time >= self.check_interval - 1:

                    # execute check each 30 seconds
                    if int(time.time()) % self.check_interval == 0:
                        
                        # heartbeat
                        if VERBOSE_DEBUG:
                            log.debug(" > HEARTBEAT: idle=%s, position=%s" % (self.idle_time, self.position))
                        
                        # save state when not yet saved
                        if not self.saved:
                            self.save_state()

                        # log statistics
                        if self.idle_processed > 0:
                            self.position = self.active_log_object.tell()
                            log.info("Messages processed from last idle period: %s" % self.idle_processed)
                            self.idle_processed = 0

                        # check rotation
                        if self.check_rotation():
                            log.info("Log file has rotated. Restarting at 0.")
                            self.active_log_object.close()
                            self.position = 0
                            if not self.open_active_log():
                                return False
                            time.sleep(1)
                            continue
                        
                        # check duration of zero-size file, need to re-open periodically
                        if self.position == 0 and not zero_size_start:
                            zero_size_start = int(time.time())
                        
                        # re-open active file
                        if zero_size_start:
                            if int(time.time()) > zero_size_start + self.reload_zero_hours * 60 * 60:
                                log.info("%s hours passed with no activity in log file. Re-opening to renew file handle." % self.reload_zero_hours)
                                self.active_log_object.close()
                                self.position = 0
                                if not self.open_active_log():
                                    return False
                                time.sleep(1)
                                zero_size_start = None
                                continue
                            
                    # check if we need to send last queued notification while in idle, each 5 minutes
                    if len(self.notification_pool) > 0:
                        if int(time.time()) % self.check_interval * 10 == 0:
                            notify_me = self.notify_check()
                            if notify_me:
                                self.notify()

                time.sleep(1)
                continue

            # we got something to read, OK

            idle_time_start = None
            zero_size_start = None
            self.saved = False
            self.position = self.active_log_object.tell()

            # save state file each 30 seconds
            if int(time.time()) % self.check_interval == 0:
                if not self.saved:
                    if self.save_time < int(time.time()):
                        self.save_state()
                    # TODO: flush database

            match = re.findall(self.pattern, line)
            if not match:
                log.debug("  > BAD LINE: %s" % line)
            else:
                snort_time      = match[0][0]
                snort_rule      = match[0][1]
                snort_name      = match[0][2]
                snort_type      = match[0][3]
                snort_priority  = int(match[0][4])
                snort_proto     = match[0][5]
                snort_src_ip    = match[0][6]
                snort_src_port  = match[0][7]
                snort_dst_ip    = match[0][8]
                snort_dst_post  = match[0][9]

                if snort_priority < 3:
                    self.notify("PR #%s" % snort_priority, snort_rule, snort_name, "%s -> %s" % (snort_src_ip, snort_dst_ip))

            self.idle_processed += 1

def main():
    log.info("***************************************************************")
    log.info("******************** SNORT READER STARTED *********************")
    log.info("********************** v.%s.%s *************************" % (VERSION, RELEASE))
    try:
        set_signals()
        atexit.register(exit_handler)

        conf = Config("reader.ini")
        if not conf:
            log.error("Configuration not available. Exiting.")
            sys.exit(1)
        reader = LogReader(conf)
        if not reader.get_log_path:
            log.error("Unable to get snort alert log path. Exiting.")
            sys.exit(1)
        if not reader.start_tail():
            log.error("Log monitoring failed! Exiting.")
            sys.exit(1)
        else:
            # this should not be the case, but whatever :)
            log.info("Log monitoring exiting without errors.")
            sys.exit(0)

    # catch generic and signal exceptions
    except SIGException:
        log.error("Processing interrupted by signal!")
        sys.exit(1)
    except SystemExit:
        pass
    except:
        log.error("Unhandled exception: %s" % traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()

#EOF