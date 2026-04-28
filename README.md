# sentinel-agent
Sentinel Agent to be installed on machines to monitor them along with its backend APIs for visualisation the logs and attacks or potential threats on a User interface
## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SENTINEL AGENT                           │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────┐ │
│  │ File         │  │ Auth         │  │ Network      │  │Proc│ │
│  │ Collector    │  │ Collector    │  │ Collector    │  │    │ │
│  │              │  │              │  │              │  │    │ │
│  │ watchdog     │  │ Linux:       │  │ psutil       │  │    │ │
│  │ inotify/     │  │ tail auth.log│  │ connections  │  │    │ │
│  │ FSEvents/    │  │              │  │ + bandwidth  │  │psut│ │
│  │ ReadDirChg   │  │ Windows:     │  │              │  │il  │ │
│  │              │  │ EventLog API │  │              │  │    │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──┬─┘ │
│         └─────────────────┴──────────────────┴─────────────┘   │
│                              │                                  │
│                    ┌─────────▼──────────┐                       │
│                    │  Event Dispatcher  │  (thread-safe queue)  │
│                    └─────────┬──────────┘                       │
│                              │                                  │
│           ┌──────────────────┼──────────────────┐              │
│           ▼                  ▼                  ▼              │
│    ┌─────────────┐  ┌──────────────┐  ┌──────────────┐        │
│    │ JSONL Files │  │   Postgres   │  │   stdout     │        │
│    │ (per-cat +  │  │ (indexed,    │  │ (pipe to     │        │
│    │  all-events)│  │  queryable)  │  │  SIEM/ELK)   │        │
│    └─────────────┘  └──────────────┘  └──────────────┘        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Universal Event Schema

Every event — regardless of source — is normalized to the same structure:

```json
{
  "event_id":        "uuid-v4",
  "timestamp":       "2026-04-07T08:32:11.123+00:00",
  "ingested_at":     "2026-04-07T08:32:11.124+00:00",
  "category":        "file | authentication | network | process | system",
  "action":          "create | read | update | delete | rename | chmod | login | login_failed | ssh_accepted | ssh_failed | sudo | connect | close | start | stop | ...",
  "outcome":         "success | failure | unknown",
  "severity":        "info | low | medium | high | critical",
  "tags":            ["filesystem", "lolbin", "suspicious_port", ...],
  "collector":       "file_watcher | auth_log | windows_eventlog | network_monitor | process_monitor",

  "host": {
    "hostname":      "my-server",
    "os_type":       "linux | windows | darwin",
    "os_version":    "...",
    "os_release":    "22.04",
    "architecture":  "x86_64",
    "ip_addresses":  ["10.0.1.5"]
  },

  "file": {
    "path":          "/etc/passwd",
    "name":          "passwd",
    "extension":     "",
    "directory":     "/etc",
    "size_bytes":    2183,
    "sha256":        "e3b0c44298fc1c149afb...",
    "sha1":          "da39a3ee5e6b4b0d3255...",
    "md5":           "d41d8cd98f00b204e980...",
    "inode":         131073,
    "permissions":   "-rw-r--r--",
    "owner":         "root",
    "group":         "root",
    "modified_at":   "2026-04-06T10:00:00+00:00",
    "old_sha256":    "previous-hash-if-modified"
  },

  "user": {
    "name":          "alice",
    "uid":           1001,
    "gid":           1001,
    "effective_uid": 0,
    "terminal":      "pts/0"
  },

  "process": {
    "pid":           4521,
    "ppid":          1200,
    "name":          "python3",
    "executable":    "/usr/bin/python3",
    "command_line":  "python3 script.py --arg",
    "user":          "alice",
    "start_time":    "2026-04-07T08:30:00+00:00",
    "sha256":        "hash-of-the-executable",
    "cpu_percent":   12.3,
    "memory_rss_mb": 45.2
  },

  "network": {
    "direction":         "outbound",
    "transport":         "tcp",
    "protocol":          "https",
    "src_ip":            "10.0.1.5",
    "src_port":          54321,
    "dst_ip":            "93.184.216.34",
    "dst_port":          443,
    "connection_status": "ESTABLISHED",
    "is_private_ip":     false
  },

  "auth": {
    "method":        "publickey",
    "source_ip":     "203.0.113.10",
    "source_port":   51234,
    "session_type":  "ssh",
    "failure_reason":"bad credentials",
    "sudo_command":  "/usr/bin/vim /etc/sudoers",
    "pam_module":    "pam_unix"
  },

  "raw_log":          "Jun 15 08:32:11 server sshd[1234]: ...",
  "risk_score":        null,
  "anomaly":           null,
  "ioc_match":         null,
  "mitre_tactic":      "Credential Access",
  "mitre_technique":   "T1110",
  "notes":             null
}
```




## Linux Usage

```
Update database credentials in src/config.py
```

# Install requirements

```bash
pip install -r requirements.txt
```

# Running programme
```bash
sudo python -m src.main
```

# If Issue occures

```
Create a virtual environment and install dependencies (Use python3 if python didn't work)
```

```bash
python -m venv venv
pip install -r requirements.txt
```

# Running programme
```bash
sudo venv/bin/python -m src.main
```




## Windows


```
Update database credentials in src/config.py
```

# Install requirements

```bash
pip install -r requirements.txt
```

# Running programme as administrator
```bash
python -m src.main
```