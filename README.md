# Splunk Security Log Collection

Lab setup for collecting Windows and Linux security logs into Splunk Enterprise, plus a few starter searches for failed logons and SSH access.

> **Status:** lab notes from January 2025, cleaned up in November 2026. This repo covers getting logs in. The detection work built on it is the write-up [Detecting Privilege Escalation in Splunk](https://hawkode.github.io/projects/splunk-privesc-detection/).

## Setup
### Splunk Enterprise
Install from the [Splunk download page](https://www.splunk.com/en_us/download/splunk-enterprise.html) (free trial or developer licence for a lab), then on Linux:
```bash
sudo /opt/splunk/bin/splunk start --accept-license
sudo /opt/splunk/bin/splunk enable boot-start
```
Create an index named `security` (Settings > Indexes > New Index), so security data doesn't land in `main`.

### Windows: Universal Forwarder
Install the Universal Forwarder on the endpoint and point it at the indexer, then set the inputs in
`C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`:
```ini
[WinEventLog://Security]
disabled = 0
index = security

[WinEventLog://System]
disabled = 0
index = security
```
Restart the forwarder service (`SplunkForwarder`) after editing.

### Linux: rsyslog and auditd
Forward syslog to the Splunk server over TCP (`@@`; a single `@` is UDP). In `/etc/rsyslog.d/90-splunk.conf`:
```
*.* @@splunk-server:514
```
Then `sudo systemctl restart rsyslog`, and add a matching TCP 514 input on the Splunk side.

Log every program execution with auditd, so commands run on the host are searchable later:
```bash
sudo auditctl -a always,exit -F arch=b64 -S execve -k command_exec
```
`auditctl` rules are lost at reboot. Put the rule in `/etc/audit/rules.d/` to keep it.

## Starter searches
Failed Windows logons by account and source:
```spl
index=security source="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, Source_Network_Address
| sort - count
```

Successful SSH password logons:
```spl
index=security "Accepted password"
| stats count by user, src_ip
```

Possible SSH brute force, more than 5 failures from one source:
```spl
index=security "Failed password"
| stats count by src_ip, user
| where count > 5
```
Field names such as `src_ip` depend on the add-on and sourcetype. Without the Splunk Add-on for Unix and Linux, extract them with `rex` first.

## Limits of this lab
- No dashboards, alerts or compliance reporting were built here. Earlier versions of this README listed them as features; they were plans, not work.
- Sending every syslog facility (`*.*`) is fine for a lab and expensive at scale. In production, forward the security-relevant facilities and use the Splunk add-ons for parsing.

## Next
- [Detecting Privilege Escalation in Splunk](https://hawkode.github.io/projects/splunk-privesc-detection/): detections for the techniques from the Windows privilege escalation lab.
- [Windows Health Monitor](https://github.com/Hawkode/Windows-Health-Monitor): writes endpoint posture findings and a heartbeat to the Application log for these forwarders to pick up.
