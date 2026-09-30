# NetScaler ADC IOC Hunt — Dissect Plugin

A [Dissect Target](https://github.com/fox-it/dissect.target) plugin for hunting compromise indicators in **Citrix NetScaler ADC / Gateway** disk images.

The plugin is intended for offline forensic analysis of NetScaler appliances. It searches the filesystem and historical logs for indicators associated with known NetScaler exploitation and post-exploitation activity, including web shells, suspicious web files, setuid persistence, configuration tampering, artifact removal, exploitation telemetry, and memory-overread activity.

## Features

The plugin performs several complementary IOC checks:

* Suspicious PHP and XHTML files in NetScaler web directories
* Suspicious `.sig` and NetScaler installer `.deb` files
* Root-owned setuid files
* SUID `/bin/sh`
* Apache/PHP configuration modifications
* Suspicious PHP handler configuration
* VPN/web-shell related files and content
* SLAPSHOT-related artifacts and telemetry
* WHIPSHOT-related web-shell indicators
* Suspicious HTTP access and exploitation requests
* Known-bad IP addresses
* Exploitation telemetry in NetScaler logs
* Suspicious `ns.log` entries
* Suspicious `rc.netscaler` modifications
* Artifact removal commands
* Suspicious memory-overread indicators
* Shell-history persistence and cleanup activity
* Rotated and gzip-compressed logs

The plugin operates directly against the forensic target and does **not** require the NetScaler appliance to be running.

## Installation

Install the Dissect Target package according to the official Dissect documentation:

```bash
pip install dissect.target
```

Clone this repository:

```bash
git clone https://github.com/<your-account>/<your-repository>.git
cd <your-repository>
```

The plugin can then be supplied to `target-query` using `--plugin-path`.

## Usage

Run the IOC hunt against a NetScaler disk image:

```bash
target-query \
    -f netscaler.ioc \
    --plugin-path /path/to/plugin \
    /path/to/netscaler-image
```

Depending on the image format and acquisition method, the target can be a disk image, forensic container, or another target supported by Dissect.

The plugin exposes the following namespace:

```text
netscaler
```

and the following exported function:

```text
netscaler.ioc
```

## Output

Results are returned using the following Dissect record type:

```text
application/netscaler/ioc
```

Each result contains fields including:

| Field         | Description                                 |
| ------------- | ------------------------------------------- |
| `ioc_name`    | Name of the detected indicator              |
| `category`    | IOC category                                |
| `path`        | File or log containing the indicator        |
| `line_number` | Matching line number for log/config matches |
| `match`       | Matching log/config content                 |
| `mode`        | File mode                                   |
| `uid`         | File owner UID                              |
| `gid`         | File owner GID                              |
| `size`        | File size                                   |
| `mtime`       | File modification time                      |

Example:

```text
<application/netscaler/ioc
    hostname='netscaler'
    domain='ns'
    ioc_name='setuid root file'
    category='setuid files'
    path='/bin/sh'
    mode='0o104755'
    uid=0
    gid=0>
```

## IOC Categories

### Suspicious web files

The plugin recursively examines known NetScaler web directories for files such as:

* `.php`
* `.xhtml`
* `.sig`
* NetScaler installer packages such as:

  * `nsgclient18.deb`
  * `nsginstaller.deb`

The `/admin_ui/` subtree is handled separately to match the scope of the original IOC checks.

### Setuid persistence

The plugin searches `/var` and `/flash` for root-owned setuid files.

It also specifically identifies suspicious SUID shell persistence, including:

```text
/bin/sh
```

The `nobody` group is resolved from `/etc/group` when available.

### Configuration tampering

The plugin checks NetScaler HTTP configuration files for indicators including:

```text
AddHandler application/x-httpd-php
```

and modifications involving:

```text
Require all denied
php_flag engine off
php_flag engine on
AliasMatch
```

It also checks relevant NetScaler configuration locations such as:

```text
/etc/httpd.conf
/nsconfig/httpd.conf
/flash/nsconfig/httpd.conf
```

### Log-based exploitation indicators

The plugin searches current and rotated logs, including gzip-compressed logs.

Examples of monitored logs include:

```text
/var/log/httpaccess*
/var/log/httperror*
/var/log/ns.log*
/var/log/notice.log*
/var/log/sh.log*
/var/log/bash.log*
```

Compressed files such as:

```text
ns.log.0.gz
httpaccess-vpn.log.19.gz
```

are automatically decompressed while being scanned.

### SLAPSHOT / WHIPSHOT indicators

The plugin contains offline checks for artifacts and content associated with the SLAPSHOT and WHIPSHOT activity described in the referenced threat-intelligence reporting.

These checks include suspicious files, web-shell content, local proxy communication, and relevant HTTP/VPN telemetry.

### Memory-overread indicators

The plugin searches `ns.log` for suspicious telemetry associated with memory-overread activity, including anomalous WSFed `request_id` values.

### Artifact removal

The plugin looks for commands and telemetry indicating attempted removal of forensic artifacts, including activity targeting:

```text
/var/core/*
```

and VPN-related log cleanup.

## Compatibility

The plugin performs a basic NetScaler compatibility check by looking for expected NetScaler filesystem locations, including:

```text
/netscaler
/nsconfig
/flash
/var/netscaler
```

If none of these directories are present, the plugin reports the target as unsupported.

## Forensic considerations

This plugin is designed for **triage and IOC hunting**, not as a standalone compromise determination mechanism.

A matching IOC should be investigated in context.

For example:

* A PHP file is not necessarily malicious.
* A 404 response does not establish successful exploitation.
* A setuid file should be evaluated against the expected appliance software baseline.
* A suspicious HTTP request may represent exploitation attempts rather than successful compromise.
* Known-bad infrastructure indicators should be correlated with timestamps and other host artifacts.

The plugin intentionally returns the underlying file metadata and matching log line where available so that investigators can perform this additional analysis.

## Log handling

The plugin searches rotated logs by matching the configured log prefix.

For example:

```text
/var/log/ns.log
/var/log/ns.log.0
/var/log/ns.log.1.gz
/var/log/ns.log.2.gz
```

Gzip-compressed logs are transparently decompressed during analysis.

Only matching lines are returned as IOC records, with the corresponding line number and a truncated copy of the matching content.

## Data source

The IOC coverage is based on publicly documented NetScaler compromise indicators, including the Google Threat Intelligence Group / Mandiant reporting:

> Defending Against Active Exploitation of Citrix NetScaler ADC and Gateway Appliances

The plugin is an offline implementation of relevant filesystem and log-based indicators and is not intended to replace the original vendor or threat-intelligence detection material.

## Limitations

The plugin has several deliberate limitations:

1. **No live response**

   It operates against a forensic target and does not communicate with a running NetScaler appliance.

2. **IOC matching is not proof of compromise**

   Detection results require forensic interpretation and correlation.

3. **Some detections are approximations**

   Where published detections use YARA or other context-dependent logic, this plugin implements equivalent offline hunting logic where practical rather than requiring those external detection engines.

4. **Log availability varies**

   Older logs may have been rotated, deleted, overwritten, or otherwise unavailable in an acquired image.

5. **Filesystem layout can vary**

   NetScaler versions and appliance configurations may differ. Absence of an IOC therefore does not establish that an appliance was never compromised.

6. **Encrypted or incomplete acquisitions**

   Missing filesystem contents or incomplete acquisitions can prevent particular checks from producing useful results.

## Development

The plugin follows the standard Dissect Target plugin model.

The main plugin class is:

```python
class NetscalerIocPlugin(Plugin):
```

with the namespace:

```python
__namespace__ = "netscaler"
```

and exported function:

```python
@export(record=NetscalerIocRecord)
def ioc(...)
```

New IOC checks can generally be added either as:

* filesystem traversal methods for file-based indicators, or
* entries in the log/configuration `GREP_RULES` collection for line-oriented indicators.

Checks requiring correlation between multiple log events should preferably be implemented as dedicated parsing logic rather than independent regular-expression rules.


## Disclaimer

This Dissect plugin is provided for legitimate digital-forensics, incident-response, malware-analysis, and defensive-security purposes.

Always validate IOC findings against the specific NetScaler software version, appliance configuration, acquisition scope, and available forensic evidence.
