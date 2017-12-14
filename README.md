# Snort Alert Log Reader

The Python script to monitor (tail) the Snort alert log file and send notifications.
Support two ways of notification:
* via email
* via the custom script

You can also send SMS notifications with [Twilio Texting](https://github.com/goooroooX/texting) script ([twilio](https://www.twilio.com) account is required).

Main features:
* support snort alert log rotation
* configurable via reader.ini
* notifications limit (one notification per 6 hours by default)
* notifications queue
* processing state saving/loading
* email notifications support information from /etc/mail.rc
* pid checking (one running copy only)

TODO:
* save parsed Snort alerts to the sqlite database
* Webmin integration

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

```
Python 2.7
CentOS 7        (tested)
  or Windows    (no email notifications, for debug only)
```

### Installing

Download and copy files, set executable flag:

```
mkdir /opt/snort_reader
cp snort_alert_reader.py /opt/snort_reader/
cp reader.ini /opt/snort_reader/
chmod +x /opt/snort_reader/snort_alert_reader.py
vim /opt/snort_reader/reader.ini
```

### Configuring

Open configuration file for editing:

```
vim /opt/snort_reader/reader.ini
```

Set up following options:

* snort_log     - the path to Snort alert log (/var/log/snort/alert by default)
* notify_cmd    - path to notification script (e.g. /opt/texting/texting). Can be empty.
* notify_email  - email address for notifications. Can be empty.

### Testing

Schedule script with crontab:

```
crontab -e
* * * * * /opt/snort_reader/snort_alert_reader.py > /dev/null 2>&1
```

Wait one minute after scheduling and verify execution:

```
tail -f /var/log/alert_snort_reader.log
```

You can also enable heartbeats with enabling VERBOSE_DEBUG in a script:

```
cd /opt/snort_reader/
vim snort_alert_reader.py
VERBOSE_DEBUG = True
:wq
kill `cat reader.pid`
```

## Authors

* **Dmitry Nikolaenya** - *reader code* - [gooorooo.com](https://gooorooo.com)

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE.md](LICENSE.md) file for details.
