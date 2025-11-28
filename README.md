# Autonomous APT Agent

APT simulation tool with 42 different capabilities for security research. Built to demonstrate real-world attack techniques used by threat actors.

Use this for learning and authorized testing only. Don't be stupid with it.

## Features

- Reconnaissance (8 tools): network scanning, system info, user activity
- Credential harvesting (5 tools): SSH keys, browser passwords, cloud creds
- Privilege escalation (3 tools): SUID binaries, sudo checks, process injection
- Persistence (5 tools): launch agents, cron jobs, encrypted payloads
- Evasion (6 tools): anti-forensics, killing monitors, clearing history
- System checks (4 tools): SIP status, VM detection, security tools
- Advanced stuff (6 tools): memory execution, remote code, injection
- Lateral movement (5 tools): network shares, service scanning, cloud access

## Install

```bash
pip install -r requirements.txt
```

Create `.env` file:
```
OLLAMA_URL=http://localhost:11434
MODEL_NAME=dolphin-unhinged
```

## Run

```bash
python main.py                # main agent
python test_passwords.py      # test credential extraction
```

## Disclaimer

For authorized testing only. You're responsible for what you do with this. Don't hack people without permission.
