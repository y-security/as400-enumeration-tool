# AS/400 (IBM i) Enumeration Tool

A Python-based enumeration tool for IBM i (AS/400) systems, built on [JTOpen (jt400.jar)](https://github.com/IBM/JTOpen) via JPype. It drives the native Host Server protocols and JDBC to perform read-only reconnaissance across network services, system security posture, identity/authority, objects, the IFS, and the database catalog — plus a few targeted/manual modules (arbitrary SQL, CL command execution, IFS path walks, data queue peeks).

> **⚠️ Authorized use only.** This tool connects to and queries live IBM i systems, and several modules (`--rmtcmd`, `--defcreds`, `--peek`) can execute commands, test credentials, or read live application data. Only run this against systems you own or have explicit written authorization to test.

> **🤖 Note on origin:** This tool was written by an LLM (Claude). It has not been independently security-reviewed or battle-tested against production IBM i environments. Treat its output as a starting point for investigation, not as ground truth — validate findings manually before acting on them, and review the code yourself before running it against anything that matters.

## Requirements

```
pip install jpype1
```

Download `jt400.jar` from the [JTOpen releases page](https://github.com/IBM/JTOpen/releases).

## Usage

```
./as400enum.py -s <host> -u <user> -p <password> -j ./jt400.jar [modules...]
```

### Connection options
| Flag | Description |
|---|---|
| `-s`, `--server` | IBM i hostname or IP |
| `-u`, `--user` | IBM i user profile |
| `-p`, `--password` | IBM i password |
| `-j`, `--jar` | Path to `jt400.jar` |
| `--ssl` | Use SSL for Host Server connections |
| `--insecure` | Allow self-signed/unverified SSL certs |

### Modules
| Flag | Description |
|---|---|
| `--all` | Run the safe, read-only module set |
| `--services` | Host server reachability & auth |
| `--ddm` | DDM/DRDA probe (446/448) |
| `--netserver` | NetServer/SMB config & shares |
| `--pwlevel` | Password level (`QPWDLVL`) |
| `--pwdaudit` | Password policy + stale/no-password users |
| `--audit` | Audit posture (`QAUD*`) |
| `--sysvals` | Bulk system value dump |
| `--users` | All user profiles |
| `--privusers` | Privileged user profiles only |
| `--groups` | Group profile memberships |
| `--functionusage` | `QIBM_*` function usage |
| `--authority` | Object/authority checks |
| `--dtaq` | Data queue objects in `--lib` |
| `--spool` | List spooled files |
| `--savf` | Save files in `--lib` |
| `--exitpoints` | Registered exit programs |
| `--scheduler` | Scheduled jobs & job queues |
| `--ifs` | Walk default IFS hot paths |
| `--sql` | Curated SQL catalog enumeration |
| `--rmtcmd` | Remote command capability probe |
| `--defcreds` | Default credential sweep (**lockout risk — opt-in only**) |

### Manual / targeted overrides
These work independently of the module flags above:

| Flag | Description |
|---|---|
| `--sql-query "SELECT ..."` | Run a single arbitrary SQL query |
| `--rmtcmd-exec "CMD"` | Run an arbitrary CL command |
| `--ifs-path <path...>` | Walk specific IFS path(s) |
| `--ifs-depth <n>` | IFS recursion depth (default 1) |
| `--authority-obj <lib/obj>` / `--authority-type <*TYPE>` | Check authority on a specific object |
| `--spool-get <job>/<user>/<jobnum>/<splf>/<splfnum>` | Retrieve a specific spooled file |
| `--defcreds-file <path>` | Credential list for `--defcreds` |
| `--peek --lib <lib> --queue <name>` | Peek the head entry of a data queue |

### Examples

```bash
# Cleartext, full read-only sweep
./as400enum.py -s 10.10.10.5 -u MYUSER -p pass -j ./jt400.jar --all

# SSL with self-signed cert, just user + authority enum
./as400enum.py -s host -u u -p p -j ./jt400.jar --ssl --insecure --users --authority

# Manual SQL against the catalog
./as400enum.py -s host -u u -p p -j ./jt400.jar \
    --sql-query "SELECT * FROM QSYS2.USER_INFO WHERE SPECIAL_AUTHORITIES LIKE '%*ALLOBJ%'"

# Targeted CL command execution
./as400enum.py -s host -u u -p p -j ./jt400.jar --rmtcmd-exec "DSPLIBL OUTPUT(*PRINT)"

# Peek a data queue
./as400enum.py -s host -u u -p p -j ./jt400.jar --peek --lib QUSRSYS --queue INTFC_LOG
```

## Related write-up

A companion blog post walking through the design and findings from using this tool is available here:

[Hacking IBM iSeries: How AI Can Be Used to Exploit Proprietary Systems](https://y-security.de/news-en/hacking-ibm-iseries-how-ai-can-be-used-to-exploit-proprietary-systems/)

## Disclaimer

This tool is provided for authorized security testing and administrative auditing purposes only. The authors/maintainers are not responsible for misuse. Always obtain proper authorization before scanning or testing any system you do not own.

# License
Released under [GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007](https://github.com/y-security/as400-enumeration-tool/blob/main/LICENSE)
