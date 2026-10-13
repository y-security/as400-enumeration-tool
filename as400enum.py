#!/usr/bin/env python3
"""
AS/400 (IBM i) Enumeration Tool
Uses jt400.jar via JPype for native IBM i Host Server and JDBC interaction.

Requirements:
    pip install jpype1
    Download jt400.jar from https://github.com/IBM/JTOpen/releases

Overview of modules (see --help for the full list):
    Network / transport : --services --ddm --netserver
    System posture      : --pwlevel --pwdaudit --audit --sysvals
    Identity / authority: --users --groups --authority --functionusage
    Objects / data      : --dtaq --spool --savf --exitpoints --scheduler
    Filesystem          : --ifs
    Database            : --sql
    Execution           : --rmtcmd
    Credential testing  : --defcreds  (lockout risk — opt-in only)

Manual / targeted overrides (work independently of the auto module flags):
    --sql-query "SELECT ..."
    --rmtcmd-exec "DSPSYSVAL QAUDCTL"
    --ifs-path /home/user
    --authority-obj QSYS/QSECOFR --authority-type *USRPRF
    --spool-get <job>/<user>/<jobnum>/<splf>/<splfnum>
    --defcreds-file ./creds.txt
    --peek --lib QGPL --queue MYQUEUE

Usage examples:
    # Cleartext, full read-only sweep
    ./enum-iseries.py -s 10.10.10.5 -u MYUSER -p pass -j ./jt400.jar --all

    # SSL with self-signed cert, just user + authority enum
    ./enum-iseries.py -s host -u u -p p -j ./jt400.jar --ssl --insecure --users --authority

    # Manual SQL against the catalog
    ./enum-iseries.py -s host -u u -p p -j ./jt400.jar \\
        --sql-query "SELECT * FROM QSYS2.USER_INFO WHERE SPECIAL_AUTHORITIES LIKE '%*ALLOBJ%'"

    # Targeted CL command execution
    ./enum-iseries.py -s host -u u -p p -j ./jt400.jar --rmtcmd-exec "DSPLIBL OUTPUT(*PRINT)"
"""

import argparse
import sys
import os
import socket
import time
import re

try:
    import jpype
    import jpype.imports
except ImportError:
    print("[!] JPype not installed. Run: pip install jpype1")
    sys.exit(1)


# ─── Constants ────────────────────────────────────────────────────────────────

BANNER = r"""
    ___   _____ __ __  ____  ____       ______
   /   | / ___// // / / __ \/ __ \     / ____/___  __  ______ ___
  / /| | \__ \/ // /_/ / / / / / /    / __/ / __ \/ / / / __ `__ \
 / ___ |___/ /__  __/ /_/ / /_/ /    / /___/ / / / /_/ / / / / / /
/_/  |_/____/  /_/  \____/\____/    /_____/_/ /_/\__,_/_/ /_/ /_/

    IBM i (AS/400) Enumeration Tool
    For authorized penetration testing only.
"""

# IBM i Host Server ports (cleartext and SSL). SSL = cleartext + 1000.
HOST_SERVERS = {
    "central":   {"port": 8470, "ssl_port": 9470, "desc": "Central Server"},
    "database":  {"port": 8471, "ssl_port": 9471, "desc": "Database (ODBC/JDBC) Server"},
    "dtaq":      {"port": 8472, "ssl_port": 9472, "desc": "Data Queue Server"},
    "netprint":  {"port": 8473, "ssl_port": 9473, "desc": "Network Print Server"},
    "file":      {"port": 8474, "ssl_port": 9474, "desc": "File (IFS) Server"},
    "rmtcmd":    {"port": 8475, "ssl_port": 9475, "desc": "Remote Command Server"},
    "signon":    {"port": 8476, "ssl_port": 9476, "desc": "Signon Server"},
}

# Special authorities to highlight on user enum
HIGH_VALUE_AUTHORITIES = [
    "*ALLOBJ", "*SECADM", "*SERVICE", "*SPLCTL", "*SAVSYS",
    "*IOSYSCFG", "*AUDIT", "*JOBCTL",
]

# Default sensitive objects the --authority module checks if no --authority-obj given
DEFAULT_SENSITIVE_OBJECTS = [
    ("QSYS",    "QSECOFR",    "*USRPRF"),
    ("QSYS",    "QSYSOPR",    "*USRPRF"),
    ("QSYS",    "QPGMR",      "*USRPRF"),
    ("QSYS",    "QUSER",      "*USRPRF"),
    ("QSYS",    "QSRV",       "*USRPRF"),
    ("QSYS",    "QSRVBAS",    "*USRPRF"),
    ("QSYS",    "QPWFSERVER", "*AUTL"),
    ("QSYS",    "QZDASOINIT", "*PGM"),
    ("QSYS",    "QCMD",       "*CMD"),
    ("QSYS",    "QCMDEXC",    "*PGM"),
    ("QGPL",    "QGPL",       "*LIB"),
    ("QUSRSYS", "QUSRSYS",    "*LIB"),
]

# Default credential list for --defcreds (user:password pairs).
DEFAULT_CREDS = [
    ("QSECOFR", "QSECOFR"),
    ("QSECOFR", "QSYS"),
    ("QSECOFR", "PASSWORD"),
    ("QSYSOPR", "QSYSOPR"),
    ("QPGMR",   "QPGMR"),
    ("QUSER",   "QUSER"),
    ("QSRV",    "QSRV"),
    ("QSRVBAS", "QSRVBAS"),
    ("SECOFR",  "SECOFR"),
    ("11111111", "11111111"),
    ("22222222", "22222222"),
]

# Default IFS paths for --ifs (shallow listing)
DEFAULT_IFS_PATHS = [
    "/",
    "/home",
    "/tmp",
    "/root",
    "/etc",
    "/QOpenSys/etc",
    "/QOpenSys/var",
    "/QIBM/UserData",
    "/QIBM/ProdData",
    "/www",
]

# IFS filename patterns worth flagging if spotted
IFS_INTERESTING_PATTERNS = [
    r"\.ssh", r"id_rsa", r"id_dsa", r"authorized_keys", r"known_hosts",
    r"\.netrc", r"\.profile", r"\.bash_history", r"\.history",
    r"passwd", r"shadow", r"secret", r"password", r"\.pem", r"\.key",
    r"\.p12", r"\.pfx", r"\.kdb", r"\.sth", r"httpd\.conf",
    r"\.env", r"config\.xml", r"web\.xml",
]
_IFS_INTERESTING_RE = re.compile("|".join(IFS_INTERESTING_PATTERNS), re.IGNORECASE)


class C:
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def ok(msg):     print(f"  {C.GREEN}[+]{C.RESET} {msg}")
def warn(msg):   print(f"  {C.YELLOW}[*]{C.RESET} {msg}")
def fail(msg):   print(f"  {C.RED}[-]{C.RESET} {msg}")
def info(msg):   print(f"  {C.CYAN}[i]{C.RESET} {msg}")
def hot(msg):    print(f"  {C.MAGENTA}[!]{C.RESET} {msg}")
def header(msg): print(f"\n{C.BOLD}{C.CYAN}{'═'*62}\n  {msg}\n{'═'*62}{C.RESET}")


# ─── Generic helpers ─────────────────────────────────────────────────────────

def _safe_str(val, default=""):
    if val is None:
        return default
    try:
        s = str(val)
        if s == "null":
            return default
        return s
    except Exception:
        return default


def _tcp_check(host, port, timeout=4):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def _truncate(s, n):
    s = _safe_str(s)
    if len(s) > n:
        return s[: n - 1] + "…"
    return s


def _print_table(columns, rows, max_col_width=40):
    if not rows:
        info("(no rows)")
        return
    widths = []
    for i, c in enumerate(columns):
        max_row_w = max((len(_truncate(r[i], max_col_width)) for r in rows), default=0)
        widths.append(min(max(len(c), max_row_w), max_col_width))

    print("    " + "  ".join(f"{columns[i]:<{widths[i]}}" for i in range(len(columns))))
    print("    " + "  ".join("─" * widths[i] for i in range(len(columns))))
    for r in rows:
        print("    " + "  ".join(f"{_truncate(r[i], widths[i]):<{widths[i]}}" for i in range(len(columns))))


def _module_guard(fn):
    """Decorator: trap module exceptions so one failure can't abort the run."""
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            fail(f"Module {fn.__name__} crashed: {e}")
            import traceback
            traceback.print_exc()
            return None
    wrapper.__name__ = fn.__name__
    return wrapper


# ─── JVM / jt400 / JDBC Bootstrap ────────────────────────────────────────────

def start_jvm(jar_path):
    if not os.path.isfile(jar_path):
        fail(f"jt400.jar not found at: {jar_path}")
        sys.exit(1)
    if not jpype.isJVMStarted():
        info(f"Starting JVM with classpath: {jar_path}")
        jpype.startJVM(classpath=[jar_path])
        ok("JVM started successfully")
    else:
        warn("JVM already running")


def install_trust_all_ssl():
    """Install a trust-all default SSLContext. Pentest only."""
    from javax.net.ssl import SSLContext, X509TrustManager, HttpsURLConnection
    from java.security import SecureRandom

    warn("Installing trust-all SSL context (certificate validation DISABLED)")

    @jpype.JImplements(X509TrustManager)
    class TrustAll:
        @jpype.JOverride
        def checkClientTrusted(self, chain, authType): pass
        @jpype.JOverride
        def checkServerTrusted(self, chain, authType): pass
        @jpype.JOverride
        def getAcceptedIssuers(self):
            X509Cert = jpype.JClass("java.security.cert.X509Certificate")
            return jpype.JArray(X509Cert)(0)

    ctx = SSLContext.getInstance("TLS")
    tm_array = jpype.JArray(X509TrustManager)([TrustAll()])
    ctx.init(None, tm_array, SecureRandom())
    SSLContext.setDefault(ctx)

    @jpype.JImplements("javax.net.ssl.HostnameVerifier")
    class TrustAllHostnames:
        @jpype.JOverride
        def verify(self, hostname, session):
            return True
    HttpsURLConnection.setDefaultHostnameVerifier(TrustAllHostnames())
    ok("Trust-all SSL context installed")


def get_as400_connection(server, user, password, use_ssl=False):
    if use_ssl:
        from com.ibm.as400.access import SecureAS400
        info(f"Connecting to {server} as {user} over SSL/TLS...")
        as400 = SecureAS400(server, user, password)
    else:
        from com.ibm.as400.access import AS400
        info(f"Connecting to {server} as {user} (cleartext)...")
        as400 = AS400(server, user, password)

    as400.setGuiAvailable(False)
    as400.validateSignon()
    transport = "SSL/TLS" if use_ssl else "cleartext"
    ok(f"Authenticated to {server} as {user} ({transport})")
    return as400


_JDBC_STATE = {"conn": None, "error": None}

def get_jdbc_connection(server, user, password, use_ssl=False):
    if _JDBC_STATE["conn"] is not None:
        return _JDBC_STATE["conn"]
    if _JDBC_STATE["error"] is not None:
        return None
    try:
        from java.sql import DriverManager
        jpype.JClass("com.ibm.as400.access.AS400JDBCDriver")

        url = f"jdbc:as400://{server};naming=system;errors=full;prompt=false;libraries=*LIBL"
        if use_ssl:
            url += ";secure=true"

        info(f"Opening JDBC connection: {url}")
        conn = DriverManager.getConnection(url, user, password)
        _JDBC_STATE["conn"] = conn
        ok("JDBC connection established")
        return conn
    except Exception as e:
        fail(f"JDBC connection failed: {e}")
        _JDBC_STATE["error"] = str(e)
        return None


def run_sql(conn, query, max_rows=500):
    """Execute a query. Returns (columns, rows) or (None, None) on error."""
    if conn is None:
        fail("No JDBC connection available")
        return None, None
    try:
        stmt = conn.createStatement()
        try:
            stmt.setMaxRows(max_rows)
        except Exception:
            pass
        rs = stmt.executeQuery(query)
        meta = rs.getMetaData()
        ncols = meta.getColumnCount()
        cols = [_safe_str(meta.getColumnLabel(i + 1)) for i in range(ncols)]
        rows = []
        n = 0
        while rs.next() and n < max_rows:
            row = []
            for i in range(ncols):
                try:
                    v = rs.getObject(i + 1)
                except Exception:
                    v = "(err)"
                row.append(_safe_str(v).strip())
            rows.append(row)
            n += 1
        rs.close()
        stmt.close()
        return cols, rows
    except Exception as e:
        fail(f"SQL error: {e}")
        return None, None


# ─── Module: Password Level ──────────────────────────────────────────────────

@_module_guard
def enum_password_level(as400):
    header("PASSWORD LEVEL (QPWDLVL)")
    from com.ibm.as400.access import SystemValue

    sv = SystemValue(as400, "QPWDLVL")
    pwdlvl = int(str(sv.getValue()))
    level_info = {
        0: ("DES encryption", "Max 10 chars, UPPERCASE only. Weakest setting.", "HIGH"),
        1: ("DES + NetServer auth", "Same as 0 plus LAN Server auth.", "HIGH"),
        2: ("SHA-1 with DES compat", "128-char mixed-case, DES fallback retained.", "MEDIUM"),
        3: ("SHA-1 only", "No DES backward compat. Mixed-case enforced.", "LOW-MEDIUM"),
        4: ("HMAC-SHA-512", "Unlimited length, no DES. Strongest available.", "LOW"),
    }
    desc, detail, risk = level_info.get(pwdlvl, ("Unknown", "Undocumented level", "UNKNOWN"))
    ok(f"QPWDLVL = {pwdlvl}")
    info(f"Method: {desc}")
    info(f"Detail: {detail}")
    if pwdlvl <= 1:
        hot(f"RISK: {risk} — DES hashes, credentials sniffable/crackable")
    elif pwdlvl == 2:
        warn(f"RISK: {risk}")
    else:
        ok(f"RISK: {risk}")


# ─── Module: System Values bulk dump ─────────────────────────────────────────

@_module_guard
def enum_sysvals(conn):
    header("SYSTEM VALUES")
    if conn is None:
        fail("Requires JDBC")
        return
    cols, rows = run_sql(conn, """
        SELECT SYSTEM_VALUE_NAME,
               COALESCE(CURRENT_CHARACTER_VALUE,
                        VARCHAR(CURRENT_NUMERIC_VALUE)) AS VALUE,
               SYSTEM_VALUE_CATEGORY
          FROM QSYS2.SYSTEM_VALUE_INFO
         ORDER BY SYSTEM_VALUE_CATEGORY, SYSTEM_VALUE_NAME
    """, max_rows=500)
    if cols:
        ok(f"Retrieved {len(rows)} system values")
        _print_table(cols, rows, max_col_width=60)


# ─── Module: Password Policy / User Sanity Audit ─────────────────────────────

@_module_guard
def enum_password_audit(as400, conn):
    header("PASSWORD POLICY AUDIT")
    from com.ibm.as400.access import SystemValue

    for name in ["QPWDLVL", "QPWDMINLEN", "QPWDMAXLEN", "QPWDEXPITV",
                 "QPWDRQDDGT", "QPWDRQDDIF", "QPWDLMTCHR", "QPWDLMTREP",
                 "QPWDPOSDIF", "QPWDVLDPGM", "QMAXSIGN", "QMAXSGNACN",
                 "QRETSVRSEC", "QRMTSIGN", "QINACTITV", "QINACTMSGQ"]:
        try:
            sv = SystemValue(as400, name)
            info(f"  {name:12s} = {_safe_str(sv.getValue()).strip()}")
        except Exception:
            fail(f"  {name:12s} = (unable to read)")

    if conn is None:
        warn("Skipping stale-password cross-check (no JDBC)")
        return

    print()
    info("Users with no password / password never changes / stale last sign-on:")
    cols, rows = run_sql(conn, """
        SELECT AUTHORIZATION_NAME,
               STATUS,
               NO_PASSWORD_INDICATOR,
               PASSWORD_CHANGE_DATE,
               PREVIOUS_SIGN_ON,
               SIGN_ON_ATTEMPTS_NOT_VALID,
               PASSWORD_EXPIRATION_INTERVAL
          FROM QSYS2.USER_INFO
         WHERE NO_PASSWORD_INDICATOR = 'YES'
            OR PASSWORD_EXPIRATION_INTERVAL = -1
            OR PASSWORD_CHANGE_DATE < CURRENT DATE - 365 DAYS
         ORDER BY PASSWORD_CHANGE_DATE NULLS FIRST
    """)
    if cols:
        _print_table(cols, rows)
        if rows:
            hot(f"{len(rows)} profile(s) with weak/stale password posture")


# ─── Module: Audit Posture ───────────────────────────────────────────────────

@_module_guard
def enum_audit_posture(as400):
    header("AUDIT POSTURE (OPSEC)")
    from com.ibm.as400.access import SystemValue
    for name in ["QAUDCTL", "QAUDLVL", "QAUDLVL2", "QCRTOBJAUD", "QAUDENDACN", "QAUDFRCLVL"]:
        try:
            sv = SystemValue(as400, name)
            val = _safe_str(sv.getValue()).strip()
            info(f"  {name:12s} = {val}")
        except Exception:
            fail(f"  {name:12s} = (unable to read)")
    try:
        sv = SystemValue(as400, "QAUDCTL")
        audctl = _safe_str(sv.getValue())
        if "*NONE" in audctl or audctl.strip() == "":
            hot("QAUDCTL = *NONE — no auditing is active. Actions not logged.")
        else:
            warn(f"Auditing active: {audctl.strip()}")
    except Exception:
        pass


# ─── Module: Service Availability ────────────────────────────────────────────

@_module_guard
def enum_services(as400, server, use_ssl=False):
    header("HOST SERVER SERVICE AVAILABILITY")
    from com.ibm.as400.access import AS400
    service_map = {
        "central":   AS400.CENTRAL,
        "database":  AS400.DATABASE,
        "dtaq":      AS400.DATAQUEUE,
        "netprint":  AS400.PRINT,
        "file":      AS400.FILE,
        "rmtcmd":    AS400.COMMAND,
        "signon":    AS400.SIGNON,
    }
    mode = "SSL/TLS" if use_ssl else "cleartext"
    info(f"Authenticated probe mode: {mode}")
    info(f"Testing {len(HOST_SERVERS)} Host Server services (both cleartext & SSL)\n")

    print(f"  {'SERVICE':<10} {'CLEAR':<14} {'SSL':<14} {'AUTH':<10} DESCRIPTION")
    print(f"  {'─'*10} {'─'*14} {'─'*14} {'─'*10} {'─'*30}")

    results = []
    for name, svc_info in HOST_SERVERS.items():
        cport, sport, desc = svc_info["port"], svc_info["ssl_port"], svc_info["desc"]
        tcp_clear = _tcp_check(server, cport)
        tcp_ssl   = _tcp_check(server, sport)

        auth_ok = False
        svc_id = service_map.get(name)
        probe_reachable = tcp_ssl if use_ssl else tcp_clear
        if probe_reachable and svc_id is not None:
            try:
                if not as400.isConnected(svc_id):
                    as400.connectService(svc_id)
                auth_ok = as400.isConnected(svc_id)
            except Exception:
                auth_ok = False

        clear_cell = f"{C.GREEN}OPEN:{cport}{C.RESET}" if tcp_clear else f"{C.RED}closed{C.RESET}      "
        ssl_cell   = f"{C.GREEN}OPEN:{sport}{C.RESET}" if tcp_ssl   else f"{C.RED}closed{C.RESET}      "
        if auth_ok:
            auth_cell = f"{C.GREEN}OK{C.RESET}        "
        elif not probe_reachable:
            auth_cell = f"{C.YELLOW}N/A{C.RESET}       "
        else:
            auth_cell = f"{C.RED}DENIED{C.RESET}    "

        print(f"  {name:<10} {clear_cell} {ssl_cell} {auth_cell} {desc}")
        results.append({"name": name, "clear": tcp_clear, "ssl": tcp_ssl, "auth": auth_ok})

    clear_count = sum(1 for r in results if r["clear"])
    ssl_count   = sum(1 for r in results if r["ssl"])
    auth_count  = sum(1 for r in results if r["auth"])
    print()
    info(f"Cleartext ports open: {clear_count}/{len(results)}")
    info(f"SSL ports open:       {ssl_count}/{len(results)}")
    info(f"Authenticated ({mode}): {auth_count}/{len(results)}")
    if clear_count > 0 and ssl_count > 0:
        warn("Both cleartext and SSL services exposed — downgrade / sniffing risk.")
    elif clear_count > 0 and ssl_count == 0:
        hot("Only cleartext services exposed — credentials traverse network in the clear.")
    elif ssl_count > 0 and clear_count == 0:
        ok("Only SSL services exposed — good posture.")


# ─── Module: DDM / DRDA ──────────────────────────────────────────────────────

@_module_guard
def enum_ddm(server):
    header("DDM / DRDA PROBE (port 446 / 448)")
    ddm_tcp = _tcp_check(server, 446)
    ddm_ssl = _tcp_check(server, 448)
    info(f"DDM cleartext 446 : {'OPEN' if ddm_tcp else 'closed'}")
    info(f"DDM SSL       448 : {'OPEN' if ddm_ssl else 'closed'}")
    if ddm_tcp or ddm_ssl:
        warn("DDM/DRDA listener present — review DDM authentication (QRMTSIGN, DDM password).")


# ─── Module: NetServer / SMB ─────────────────────────────────────────────────

@_module_guard
def enum_netserver(server, conn):
    header("NETSERVER / SMB")
    for p in (139, 445):
        info(f"TCP {p:<4} : {'OPEN' if _tcp_check(server, p) else 'closed'}")

    if conn is None:
        warn("No JDBC — cannot enumerate SERVER_SHARE_INFO. Use `smbclient -L` externally.")
        return

    info("\nShares:")
    cols, rows = run_sql(conn, """
        SELECT SERVER_SHARE_NAME, SHARE_TYPE, PERMISSIONS,
               PATH_NAME, TEXT_DESCRIPTION, MAXIMUM_USERS
          FROM QSYS2.SERVER_SHARE_INFO
         ORDER BY SERVER_SHARE_NAME
    """)
    if cols and rows:
        _print_table(cols, rows, max_col_width=50)
        readable = [r for r in rows if "READ" in _safe_str(r[2]).upper()]
        writable = [r for r in rows if "WRITE" in _safe_str(r[2]).upper() or "ALL" in _safe_str(r[2]).upper()]
        info(f"Shares: {len(rows)} total, {len(readable)} readable, {len(writable)} writable")

    info("\nActive sessions (if permitted):")
    cols, rows = run_sql(conn, "SELECT * FROM QSYS2.SERVER_SESSION_INFO FETCH FIRST 20 ROWS ONLY")
    if cols and rows:
        _print_table(cols, rows)


# ─── Module: User profiles ───────────────────────────────────────────────────

@_module_guard
def enum_users(conn, only_privileged=False):
    header("USER PROFILES" + (" (privileged only)" if only_privileged else ""))
    if conn is None:
        fail("Requires JDBC")
        return
    where = ""
    if only_privileged:
        priv = " OR ".join(f"SPECIAL_AUTHORITIES LIKE '%{a}%'" for a in HIGH_VALUE_AUTHORITIES)
        where = f" WHERE ({priv})"
    sql = f"""
        SELECT AUTHORIZATION_NAME, STATUS, USER_CLASS_NAME,
               SPECIAL_AUTHORITIES, GROUP_PROFILE_NAME,
               PREVIOUS_SIGN_ON, SIGN_ON_ATTEMPTS_NOT_VALID,
               PASSWORD_CHANGE_DATE, NO_PASSWORD_INDICATOR,
               TEXT_DESCRIPTION
          FROM QSYS2.USER_INFO
          {where}
         ORDER BY AUTHORIZATION_NAME
    """
    cols, rows = run_sql(conn, sql, max_rows=2000)
    if not cols:
        return
    ok(f"Found {len(rows)} user profile(s)")
    _print_table(cols, rows)

    flagged = []
    for r in rows:
        specauth = _safe_str(r[3]).upper()
        hits = [a for a in HIGH_VALUE_AUTHORITIES if a in specauth]
        if hits:
            flagged.append((r[0], hits, _safe_str(r[1])))
    if flagged:
        print()
        hot(f"{len(flagged)} privileged profile(s):")
        for name, hits, status in flagged:
            marker = C.GREEN + "enabled" + C.RESET if "ENABLED" in status.upper() else C.RED + status + C.RESET
            print(f"     {name:<12} [{marker}]  {', '.join(hits)}")


# ─── Module: Group membership ────────────────────────────────────────────────

@_module_guard
def enum_groups(conn):
    header("GROUP PROFILES & MEMBERSHIP")
    if conn is None:
        fail("Requires JDBC")
        return
    cols, rows = run_sql(conn, """
        SELECT GROUP_PROFILE_NAME, USER_PROFILE_NAME
          FROM QSYS2.GROUP_PROFILE_ENTRIES
         ORDER BY GROUP_PROFILE_NAME, USER_PROFILE_NAME
    """, max_rows=5000)
    if not cols:
        return
    ok(f"{len(rows)} group membership entries")
    _print_table(cols, rows)


# ─── Module: Function usage ──────────────────────────────────────────────────

@_module_guard
def enum_function_usage(conn):
    header("FUNCTION USAGE (QIBM_*)")
    if conn is None:
        fail("Requires JDBC")
        return
    cols, rows = run_sql(conn, """
        SELECT FUNCTION_ID, USER_NAME, USAGE, USER_TYPE, FUNCTION_GROUP
          FROM QSYS2.FUNCTION_USAGE
         ORDER BY FUNCTION_ID, USER_NAME
    """, max_rows=2000)
    if cols:
        ok(f"{len(rows)} function usage entries")
        _print_table(cols, rows)


# ─── Module: Object authority ────────────────────────────────────────────────

@_module_guard
def enum_object_authority(as400, targets):
    header("OBJECT AUTHORITY")
    from com.ibm.as400.access import Permission
    print(f"  {'OBJECT':<30} {'USER':<12} {'DATA_AUTH':<12} {'OBJ_AUTH':<25} AUTL")
    print(f"  {'─'*30} {'─'*12} {'─'*12} {'─'*25} {'─'*15}")
    for lib, obj, objtype in targets:
        if objtype == "*LIB":
            path = f"/QSYS.LIB/{obj}.LIB"
        else:
            ext = objtype.lstrip("*").lower()
            path = f"/QSYS.LIB/{lib}.LIB/{obj}.{ext}"
        label = f"{lib}/{obj} ({objtype})"
        try:
            perm = Permission(as400, path)
            authl = _safe_str(perm.getAuthorizationList())
            users = list(perm.getUserPermissions())
            if not users:
                warn(f"  {label:<30} (no user permissions returned)")
                continue
            for up in users:
                uname = _safe_str(up.getUserID())
                data_authorities = []
                for a in ("Read", "Write", "Execute", "Delete", "Update"):
                    try:
                        if getattr(up, f"is{a}")():
                            data_authorities.append(a[0])
                    except Exception:
                        pass
                obj_authorities = []
                for a in ("ObjectManagement", "ObjectOperational", "ObjectExistence",
                          "ObjectAlter", "ObjectReference"):
                    try:
                        if getattr(up, f"is{a}")():
                            obj_authorities.append(a)
                    except Exception:
                        pass
                print(f"  {label:<30} {uname:<12} "
                      f"{''.join(data_authorities):<12} "
                      f"{','.join(obj_authorities)[:24]:<25} "
                      f"{authl}")
        except Exception as e:
            fail(f"  {label}: {e}")


# ─── Module: Data Queues ─────────────────────────────────────────────────────

@_module_guard
def enum_data_queues(as400, libraries):
    header("DATA QUEUES")
    from com.ibm.as400.access import ObjectList, ObjectDescription
    total = 0
    for lib in libraries:
        lib = lib.strip().upper()
        info(f"Scanning library: {lib}")
        try:
            obj_list = ObjectList(as400, lib, "*ALL", "*DTAQ")
            for attr in (ObjectDescription.EXTENDED_ATTRIBUTE,
                         ObjectDescription.TEXT_DESCRIPTION,
                         ObjectDescription.CREATION_DATE,
                         ObjectDescription.OWNER):
                obj_list.addObjectAttributeToRetrieve(attr)
            obj_list.load()
            count = obj_list.getLength()
            if count == 0:
                warn(f"  No DTAQs in {lib} (or no authority)")
                continue
            ok(f"  Found {count} DTAQ in {lib}:")
            print(f"    {'QUEUE':<12} {'OWNER':<12} {'CREATED':<22} DESCRIPTION")
            print(f"    {'─'*12} {'─'*12} {'─'*22} {'─'*30}")
            for i in range(count):
                obj = obj_list.getObjects(i, 1)[0]
                name    = _safe_str(obj.getValueAsString(ObjectDescription.NAME)).strip()
                owner   = _safe_str(obj.getValueAsString(ObjectDescription.OWNER)).strip() or "(n/a)"
                created = _safe_str(obj.getValue(ObjectDescription.CREATION_DATE))[:21] or "(n/a)"
                text    = _safe_str(obj.getValueAsString(ObjectDescription.TEXT_DESCRIPTION)).strip() or "(none)"
                print(f"    {name:<12} {owner:<12} {created:<22} {text}")
                total += 1
        except Exception as e:
            err = str(e)
            if "CPF2189" in err or "not authorized" in err.lower():
                fail(f"  Not authorized to {lib}")
            elif "CPF9810" in err or "not found" in err.lower():
                fail(f"  Library {lib} does not exist")
            else:
                fail(f"  Error scanning {lib}: {e}")
    print()
    info(f"Total data queues found: {total}")


@_module_guard
def peek_data_queue(as400, library, queue_name, timeout=5):
    header(f"DATA QUEUE PEEK: {library}/{queue_name}")
    from com.ibm.as400.access import DataQueue
    path = f"/QSYS.LIB/{library.upper()}.LIB/{queue_name.upper()}.DTAQ"
    dq = DataQueue(as400, path)
    info(f"Peeking at {path} (timeout={timeout}s)...")
    entry = dq.peek(timeout)
    if entry is None:
        warn("Queue is empty or no entry arrived within timeout")
        return
    data = entry.getString()
    sender = "(n/a)"
    try:
        s = entry.getSenderInformation()
        if s:
            sender = _safe_str(s.getUser()).strip()
    except Exception:
        pass
    ok("Entry received!")
    info(f"  Sender: {sender}")
    info(f"  Length: {len(data)} bytes")
    info(f"  Data  : {repr(data[:200])}")
    if len(data) > 200:
        warn(f"  (truncated, full length {len(data)})")


# ─── Module: Save files ──────────────────────────────────────────────────────

@_module_guard
def enum_savfs(as400, libraries):
    header("SAVE FILES (*SAVF)")
    from com.ibm.as400.access import ObjectList, ObjectDescription
    total = 0
    for lib in libraries:
        lib = lib.strip().upper()
        info(f"Scanning library: {lib}")
        try:
            obj_list = ObjectList(as400, lib, "*ALL", "*SAVF")
            obj_list.addObjectAttributeToRetrieve(ObjectDescription.OWNER)
            obj_list.addObjectAttributeToRetrieve(ObjectDescription.TEXT_DESCRIPTION)
            obj_list.addObjectAttributeToRetrieve(ObjectDescription.SIZE)
            obj_list.addObjectAttributeToRetrieve(ObjectDescription.CREATION_DATE)
            obj_list.load()
            n = obj_list.getLength()
            if n == 0:
                warn(f"  No SAVFs in {lib}")
                continue
            ok(f"  {n} SAVF in {lib}:")
            print(f"    {'NAME':<12} {'OWNER':<12} {'SIZE':<12} {'CREATED':<22} DESCRIPTION")
            print(f"    {'─'*12} {'─'*12} {'─'*12} {'─'*22} {'─'*30}")
            for i in range(n):
                obj = obj_list.getObjects(i, 1)[0]
                name    = _safe_str(obj.getValueAsString(ObjectDescription.NAME)).strip()
                owner   = _safe_str(obj.getValueAsString(ObjectDescription.OWNER)).strip()
                size    = _safe_str(obj.getValue(ObjectDescription.SIZE))
                created = _safe_str(obj.getValue(ObjectDescription.CREATION_DATE))[:21]
                text    = _safe_str(obj.getValueAsString(ObjectDescription.TEXT_DESCRIPTION)).strip()
                print(f"    {name:<12} {owner:<12} {size:<12} {created:<22} {text}")
                total += 1
        except Exception as e:
            err = str(e)
            if "CPF2189" in err:
                fail(f"  Not authorized to {lib}")
            elif "CPF9810" in err:
                fail(f"  Library {lib} not found")
            else:
                fail(f"  {lib}: {e}")
    print()
    info(f"Total SAVFs: {total}")


# ─── Module: Spooled files ───────────────────────────────────────────────────

@_module_guard
def enum_spool(conn, limit=100, user_filter=None):
    header("SPOOLED FILES")
    if conn is None:
        fail("Requires JDBC")
        return
    where = ""
    if user_filter:
        where = f" WHERE USER_NAME = '{user_filter.upper()}'"
    cols, rows = run_sql(conn, f"""
        SELECT SPOOLED_FILE_NAME, USER_NAME, JOB_NAME, JOB_USER, JOB_NUMBER,
               SPOOLED_FILE_NUMBER, OUTPUT_QUEUE_NAME, OUTPUT_QUEUE_LIBRARY_NAME,
               TOTAL_PAGES, STATUS, USER_DATA, CREATE_TIMESTAMP
          FROM QSYS2.OUTPUT_QUEUE_ENTRIES_BASIC
          {where}
         ORDER BY CREATE_TIMESTAMP DESC
         FETCH FIRST {limit} ROWS ONLY
    """, max_rows=limit)
    if cols:
        ok(f"{len(rows)} spooled file(s)")
        _print_table(cols, rows, max_col_width=25)
        if rows:
            warn("Spool content often contains passwords / PII. Use --spool-get to dump a specific file.")
            info("Format for --spool-get: <jobname>/<jobuser>/<jobnumber>/<splf_name>/<splf_number>")


@_module_guard
def spool_get(as400, spec):
    header(f"SPOOL FILE DUMP: {spec}")
    parts = spec.split("/")
    if len(parts) != 5:
        fail("Expected format: jobname/jobuser/jobnumber/splf_name/splf_number")
        return
    job_name, job_user, job_num, splf_name, splf_num = parts
    from com.ibm.as400.access import SpooledFile, PrintObject, PrintParameterList

    sf = SpooledFile(as400, splf_name.upper(), int(splf_num), job_name.upper(),
                     job_user.upper(), job_num)
    info(f"Opening {splf_name}/{splf_num} for job {job_name}/{job_user}/{job_num}")

    ppl = PrintParameterList()
    try:
        ppl.setParameter(PrintObject.ATTR_MFGTYPE, "*WSCST")
        ppl.setParameter(PrintObject.ATTR_WORKSTATION_CUST_OBJECT,
                         "/QSYS.LIB/QWPDEFAULT.WSCST")
    except Exception:
        pass

    try:
        stream = sf.getTransformedInputStream(ppl)
    except Exception as e:
        fail(f"Transformed stream failed, falling back to raw: {e}")
        stream = sf.getInputStream()

    from java.io import ByteArrayOutputStream
    baos = ByteArrayOutputStream()
    buf = jpype.JArray(jpype.JByte)(4096)
    total = 0
    while True:
        n = stream.read(buf)
        if n < 0:
            break
        baos.write(buf, 0, n)
        total += n
        if total > 1024 * 1024:
            warn("Hit 1MB cap, truncating")
            break
    stream.close()
    raw = bytes(baos.toByteArray())
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        text = repr(raw[:2048])
    ok(f"Retrieved {total} bytes")
    print("\n" + "─" * 62)
    print(text[:8000])
    if len(text) > 8000:
        warn(f"(output truncated — full length {len(text)} chars)")
    print("─" * 62 + "\n")


# ─── Module: Exit points ─────────────────────────────────────────────────────

@_module_guard
def enum_exit_points(conn):
    header("EXIT POINTS / REGISTERED EXIT PROGRAMS")
    if conn is None:
        fail("Requires JDBC")
        return
    cols, rows = run_sql(conn, """
        SELECT EXIT_POINT, EXIT_POINT_FORMAT, EXIT_PROGRAM_NUMBER,
               EXIT_PROGRAM_LIBRARY, EXIT_PROGRAM, TEXT_DESCRIPTION
          FROM QSYS2.EXIT_PROGRAM_INFO
         ORDER BY EXIT_POINT, EXIT_PROGRAM_NUMBER
    """, max_rows=2000)
    if cols:
        ok(f"{len(rows)} registered exit program(s)")
        _print_table(cols, rows, max_col_width=35)
        if rows:
            warn("Exit programs run in-band with host server traffic — review for priv-esc / persistence.")


# ─── Module: Scheduler ───────────────────────────────────────────────────────

@_module_guard
def enum_scheduler(conn):
    header("JOB SCHEDULER")
    if conn is None:
        fail("Requires JDBC")
        return
    info("\nQSYS2.SCHEDULED_JOB_INFO:")
    cols, rows = run_sql(conn, """
        SELECT SCHEDULED_JOB_NAME, STATUS, JOB_USER, NEXT_SUBMISSION_DATE,
               COMMAND_STRING, TEXT_DESCRIPTION
          FROM QSYS2.SCHEDULED_JOB_INFO
         ORDER BY NEXT_SUBMISSION_DATE
    """, max_rows=500)
    if cols:
        ok(f"{len(rows)} scheduled job(s)")
        _print_table(cols, rows, max_col_width=50)

    info("\nQSYS2.JOB_QUEUE_INFO (top queues by depth):")
    cols, rows = run_sql(conn, """
        SELECT JOB_QUEUE_NAME, JOB_QUEUE_LIBRARY, NUMBER_OF_JOBS, STATUS
          FROM QSYS2.JOB_QUEUE_INFO
         ORDER BY NUMBER_OF_JOBS DESC
         FETCH FIRST 25 ROWS ONLY
    """)
    if cols:
        _print_table(cols, rows)


# ─── Module: IFS walker ──────────────────────────────────────────────────────

@_module_guard
def enum_ifs(as400, paths, depth=1):
    header("IFS WALK")
    from com.ibm.as400.access import IFSFile

    def _walk(path, current_depth):
        try:
            f = IFSFile(as400, path)
            if not f.exists():
                warn(f"  {path} : does not exist")
                return
            if not f.isDirectory():
                try:
                    owner = _safe_str(f.getOwnerName())
                except Exception:
                    owner = "?"
                size = 0
                try:
                    size = f.length()
                except Exception:
                    pass
                info(f"  FILE {path} owner={owner} size={size}")
                return
            listing = f.list()
            if listing is None:
                warn(f"  {path} : unable to list (no authority?)")
                return
            info(f"  {path}  ({len(listing)} entries)")
            flagged = []
            for name in listing:
                child_path = path.rstrip("/") + "/" + str(name)
                try:
                    ch = IFSFile(as400, child_path)
                    marker = "d" if ch.isDirectory() else "-"
                    owner = "?"
                    try:
                        owner = _safe_str(ch.getOwnerName())
                    except Exception:
                        pass
                    size = 0
                    try:
                        size = ch.length()
                    except Exception:
                        pass
                    print(f"    {marker} {owner:<12} {size:>10} {child_path}")
                    if _IFS_INTERESTING_RE.search(str(name)):
                        flagged.append(child_path)
                    if current_depth < depth and ch.isDirectory():
                        _walk(child_path, current_depth + 1)
                except Exception as e:
                    fail(f"    ? {child_path} : {e}")
            for p in flagged:
                hot(f"  Interesting filename: {p}")
        except Exception as e:
            fail(f"  {path} : {e}")

    for p in paths:
        _walk(p, 0)


# ─── Module: Remote Command Execution ────────────────────────────────────────

@_module_guard
def enum_rmtcmd(as400, custom_cmd=None):
    header("REMOTE COMMAND EXECUTION" + (" (custom)" if custom_cmd else " (capability test)"))
    from com.ibm.as400.access import CommandCall
    cc = CommandCall(as400)

    if custom_cmd:
        cmds = [(custom_cmd, "user-supplied")]
    else:
        cmds = [
            ("DSPLIBL OUTPUT(*PRINT)",                    "list user lib list"),
            ("DSPSYSVAL SYSVAL(QAUDCTL) OUTPUT(*PRINT)",  "read QAUDCTL"),
            ("DSPUSRPRF USRPRF(*CURRENT) OUTPUT(*PRINT)", "view own user profile"),
            ("WRKACTJOB OUTPUT(*PRINT)",                  "active jobs (*JOBCTL helps)"),
            ("DSPSECAUD",                                 "display security audit settings"),
            ("DSPNETA OUTPUT(*PRINT)",                    "network attributes"),
        ]

    for cmd, note in cmds:
        info(f"Running: {cmd}   [{note}]")
        try:
            result = cc.run(cmd)
            if result:
                ok("  executed OK")
            else:
                fail("  returned false")
            for msg in cc.getMessageList():
                mid = _safe_str(msg.getID())
                sev = msg.getSeverity()
                txt = _safe_str(msg.getText())
                level = hot if sev >= 30 else (warn if sev >= 10 else info)
                level(f"    [{mid} sev={sev}] {txt}")
        except Exception as e:
            fail(f"  CommandCall exception: {e}")


# ─── Module: SQL enumeration / manual query ──────────────────────────────────

SQL_CATALOG_QUERIES = [
    ("Environment info", "SELECT * FROM SYSIBMADM.ENV_SYS_INFO"),
    ("Environment variables",
     "SELECT * FROM QSYS2.ENVIRONMENT_VARIABLE_INFO FETCH FIRST 50 ROWS ONLY"),
    ("PTF group level", """
        SELECT PTF_GROUP_NAME, PTF_GROUP_LEVEL, PTF_GROUP_STATUS, PTF_GROUP_DESCRIPTION
          FROM QSYS2.GROUP_PTF_INFO ORDER BY PTF_GROUP_NAME FETCH FIRST 50 ROWS ONLY
    """),
    ("Authorization lists", """
        SELECT AUTHORIZATION_LIST, OWNER, PRIMARY_GROUP, TEXT_DESCRIPTION
          FROM QSYS2.AUTHORIZATION_LIST_INFO ORDER BY AUTHORIZATION_LIST
    """),
    ("Columns named like password/secret/token", """
        SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE
          FROM QSYS2.SYSCOLUMNS
         WHERE UPPER(COLUMN_NAME) LIKE '%PASSW%'
            OR UPPER(COLUMN_NAME) LIKE '%PWD%'
            OR UPPER(COLUMN_NAME) LIKE '%SECRET%'
            OR UPPER(COLUMN_NAME) LIKE '%TOKEN%'
            OR UPPER(COLUMN_NAME) LIKE '%APIKEY%'
            OR UPPER(COLUMN_NAME) LIKE '%CREDIT%'
         FETCH FIRST 200 ROWS ONLY
    """),
    ("Recently modified objects (30 days)", """
        SELECT OBJSCHEMA, OBJNAME, OBJTYPE, OBJOWNER, CHANGE_TIMESTAMP
          FROM TABLE(QSYS2.OBJECT_STATISTICS('*ALLUSR', '*ALL')) AS X
         WHERE CHANGE_TIMESTAMP > CURRENT TIMESTAMP - 30 DAYS
         ORDER BY CHANGE_TIMESTAMP DESC
         FETCH FIRST 50 ROWS ONLY
    """),
]

@_module_guard
def enum_sql(conn):
    header("SQL CATALOG ENUMERATION")
    if conn is None:
        fail("Requires JDBC")
        return
    for title, q in SQL_CATALOG_QUERIES:
        info(f"\n── {title} ──")
        cols, rows = run_sql(conn, q, max_rows=200)
        if cols:
            ok(f"  {len(rows)} row(s)")
            _print_table(cols, rows, max_col_width=35)


@_module_guard
def run_custom_sql(conn, query):
    header("MANUAL SQL QUERY")
    info(f"Query: {query}")
    if conn is None:
        fail("Requires JDBC")
        return
    cols, rows = run_sql(conn, query, max_rows=2000)
    if cols:
        ok(f"{len(rows)} row(s) returned")
        _print_table(cols, rows, max_col_width=60)


# ─── Module: Default credential sweep ────────────────────────────────────────

def confirm_defcreds_risk(cred_count, qmaxsign, aggressive, acknowledged=False, creds_source="built-in default list"):
    """
    Block entry to enum_default_creds until the operator explicitly acknowledges
    the lockout risk. Returns True to proceed, False to skip the module.
    """
    print()
    print(f"{C.BOLD}{C.RED}{'█'*62}{C.RESET}")
    print(f"{C.BOLD}{C.RED}  HIGH RISK ACTION — DEFAULT CREDENTIAL SWEEP{C.RESET}")
    print(f"{C.BOLD}{C.RED}{'█'*62}{C.RESET}")
    print()
    warn("This module will attempt IBM i authentication with multiple")
    warn("username/password combinations against real user profiles.")
    print()
    hot("What could go wrong:")
    print(f"      {C.RED}•{C.RESET} Failed signons increment SIGN_ON_ATTEMPTS_NOT_VALID on each profile")
    print(f"      {C.RED}•{C.RESET} Reaching QMAXSIGN triggers QMAXSGNACN — profiles may be DISABLED")
    print(f"      {C.RED}•{C.RESET} Every attempt is logged (QHST, audit journal, QSYSOPR msgq)")
    print(f"      {C.RED}•{C.RESET} SIEMs / MFA gateways WILL light up — not a stealthy test")
    print(f"      {C.RED}•{C.RESET} Disabling QSECOFR on an LPAR you can't console into is a Bad Day")
    print()
    info("Guardrails currently in effect:")
    budget_note = "FULL QMAXSIGN (no safety buffer)" if aggressive else f"QMAXSIGN - 2"
    print(f"      {C.CYAN}•{C.RESET} Per-profile attempt budget : {budget_note}")
    print(f"      {C.CYAN}•{C.RESET} QMAXSIGN detected          : {qmaxsign if qmaxsign is not None else '(unreadable, fallback=3)'}")
    print(f"      {C.CYAN}•{C.RESET} Credential source           : {creds_source}")
    print(f"      {C.CYAN}•{C.RESET} Total candidate pairs       : {cred_count}")
    print(f"      {C.CYAN}•{C.RESET} Inter-attempt delay         : 0.3s")
    print()
    warn("If any of the following are true, STOP and reconsider:")
    print(f"      {C.YELLOW}•{C.RESET} You do not have written authorization covering credential attacks")
    print(f"      {C.YELLOW}•{C.RESET} This is a production system during business hours")
    print(f"      {C.YELLOW}•{C.RESET} You have no contact who can reset a locked profile")
    print(f"      {C.YELLOW}•{C.RESET} QMAXSGNACN is set to *DISABLE (can't be read without auth)")
    print()

    if acknowledged:
        hot("Non-interactive acknowledgment provided via --defcreds-acknowledge")
        print()
        return True

    if not sys.stdin.isatty():
        fail("stdin is not a TTY and --defcreds-acknowledge was not passed.")
        fail("Refusing to run credential sweep non-interactively without explicit ack.")
        return False

    try:
        prompt = f"  {C.MAGENTA}[?]{C.RESET} Type {C.BOLD}I UNDERSTAND THE RISK{C.RESET} to proceed (anything else aborts): "
        resp = input(prompt).strip()
    except (KeyboardInterrupt, EOFError):
        print()
        fail("Aborted by user (Ctrl-C / EOF)")
        return False

    if resp != "I UNDERSTAND THE RISK":
        fail(f"Acknowledgment string did not match (got: {resp!r})")
        fail("Credential sweep SKIPPED.")
        return False

    print()
    ok("Acknowledgment received — proceeding with credential sweep")
    print()
    return True


@_module_guard
def enum_default_creds(server, use_ssl, qmaxsign=None, creds=None, aggressive=False):
    header("DEFAULT CREDENTIAL SWEEP")
    hot("Lockout risk — respecting QMAXSIGN budget")

    REASONS = {
        1:  "PASSWORD EXPIRED (but correct!)",
        2:  "password incorrect",
        3:  "password incorrect, user will be disabled soon",
        4:  "user profile DISABLED",
        5:  "user profile unknown",
        6:  "password correct",
        7:  "user profile cannot sign on",
        8:  "signon disabled after max attempts",
        20: "generic signon error",
    }

    if creds is None:
        creds = DEFAULT_CREDS[:]
    info(f"Testing {len(creds)} credential pair(s)")

    if qmaxsign is None:
        qmaxsign = 3
    budget = max(1, qmaxsign - (0 if aggressive else 2))
    info(f"Per-profile attempt budget: {budget} (QMAXSIGN={qmaxsign}, aggressive={aggressive})")

    from collections import defaultdict
    by_user = defaultdict(list)
    for u, p in creds:
        by_user[u.upper()].append(p)

    hits = []
    for user, pwlist in by_user.items():
        pwlist = pwlist[:budget]
        info(f"\n  → {user}  ({len(pwlist)} pwd candidate(s))")
        for pw in pwlist:
            try:
                if use_ssl:
                    from com.ibm.as400.access import SecureAS400 as Cls
                else:
                    from com.ibm.as400.access import AS400 as Cls
                probe = Cls(server, user, pw)
                probe.setGuiAvailable(False)
                probe.validateSignon()
                ok(f"    VALID  {user}:{pw}")
                hits.append((user, pw, "valid"))
                probe.disconnectAllServices()
                break
            except Exception as e:
                msg = str(e)
                reason_code = None
                m = re.search(r"reason code (\d+)", msg.lower())
                if m:
                    reason_code = int(m.group(1))
                reason = REASONS.get(reason_code, msg[:80])

                if reason_code == 1:
                    hot(f"    EXPIRED-BUT-CORRECT  {user}:{pw}   [{reason}]")
                    hits.append((user, pw, "expired_valid"))
                    break
                elif reason_code == 4:
                    fail(f"    disabled             {user}")
                    break
                elif reason_code == 5:
                    fail(f"    unknown              {user}")
                    break
                else:
                    fail(f"    {user}:{pw}   [{reason}]")
            time.sleep(0.3)

    print()
    if hits:
        hot(f"{len(hits)} credential hit(s):")
        for u, p, s in hits:
            print(f"    {s:<15} {u}:{p}")
    else:
        info("No default credentials valid.")


# ─── Main / CLI ──────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="AS/400 (IBM i) Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    conn = parser.add_argument_group("Connection")
    conn.add_argument("-s", "--server",   required=True, help="IBM i hostname or IP")
    conn.add_argument("-u", "--user",     required=True, help="IBM i user profile")
    conn.add_argument("-p", "--password", required=True, help="IBM i password")
    conn.add_argument("-j", "--jar",      required=True, help="Path to jt400.jar")
    conn.add_argument("--ssl",            action="store_true",
                      help="Use SSL/TLS (SecureAS400 + JDBC secure=true)")
    conn.add_argument("--insecure",       action="store_true",
                      help="With --ssl: disable cert & hostname validation")

    mods = parser.add_argument_group("Modules (pick one or more; --all runs the safe set)")
    mods.add_argument("--all",           action="store_true",
                      help="Run all READ-ONLY modules (excludes --defcreds, --peek, --spool-get)")
    mods.add_argument("--pwlevel",       action="store_true", help="Password level (QPWDLVL)")
    mods.add_argument("--pwdaudit",      action="store_true", help="Password policy + stale/no-password users")
    mods.add_argument("--audit",         action="store_true", help="Audit posture (QAUD*)")
    mods.add_argument("--sysvals",       action="store_true", help="Bulk system value dump")
    mods.add_argument("--services",      action="store_true", help="Host server reachability & auth")
    mods.add_argument("--ddm",           action="store_true", help="DDM/DRDA probe (446/448)")
    mods.add_argument("--netserver",     action="store_true", help="NetServer/SMB config & shares")
    mods.add_argument("--users",         action="store_true", help="All user profiles")
    mods.add_argument("--privusers",     action="store_true", help="Privileged user profiles only")
    mods.add_argument("--groups",        action="store_true", help="Group profile memberships")
    mods.add_argument("--functionusage", action="store_true", help="QIBM_* function usage")
    mods.add_argument("--authority",     action="store_true",
                      help="Object authority on built-in sensitive list")
    mods.add_argument("--dtaq",          action="store_true", help="Data queue objects in --lib")
    mods.add_argument("--spool",         action="store_true", help="List spooled files")
    mods.add_argument("--savf",          action="store_true", help="Save files in --lib")
    mods.add_argument("--exitpoints",    action="store_true", help="Registered exit programs")
    mods.add_argument("--scheduler",     action="store_true", help="Scheduled jobs & job queues")
    mods.add_argument("--ifs",           action="store_true", help="Walk default IFS hot paths")
    mods.add_argument("--sql",           action="store_true", help="Curated SQL catalog enum")
    mods.add_argument("--rmtcmd",        action="store_true", help="Remote command capability probe")
    mods.add_argument("--defcreds",      action="store_true",
                      help="Default credential sweep (LOCKOUT RISK — explicit opt-in)")

    man = parser.add_argument_group("Manual / targeted overrides")
    man.add_argument("--sql-query",       type=str, help="Run a single arbitrary SQL query")
    man.add_argument("--rmtcmd-exec",     type=str, help="Run an arbitrary CL command")
    man.add_argument("--ifs-path",        nargs="+", help="Walk specific IFS path(s) instead of defaults")
    man.add_argument("--ifs-depth",       type=int, default=1, help="IFS recursion depth (default 1)")
    man.add_argument("--authority-obj",   type=str,
                      help="Check authority on LIB/OBJ (used with --authority-type)")
    man.add_argument("--authority-type",  type=str, default="*FILE",
                      help="Object type for --authority-obj (e.g. *USRPRF, *LIB, *PGM)")
    man.add_argument("--spool-get",       type=str,
                      help="Dump one spooled file: jobname/jobuser/jobnum/splf/splfnum")
    man.add_argument("--spool-user",      type=str,
                      help="Filter --spool listing to this user profile")
    man.add_argument("--defcreds-file",   type=str,
                      help="Custom creds file (user:password per line) for --defcreds")
    man.add_argument("--defcreds-aggressive", action="store_true",
                      help="With --defcreds: use full QMAXSIGN budget (riskier)")
    man.add_argument("--defcreds-acknowledge", action="store_true",
                      help="Skip the interactive risk-acknowledgment prompt for --defcreds "
                           "(required if stdin is not a TTY — scripted/automated runs)")
    man.add_argument("--peek",            action="store_true", help="Peek one data queue (--lib --queue)")

    opts = parser.add_argument_group("Options")
    opts.add_argument("--lib",     nargs="+", default=["QGPL", "QUSRSYS"],
                      help="Libraries for --dtaq / --savf (default: QGPL QUSRSYS)")
    opts.add_argument("--queue",   type=str, default=None,  help="Queue name for --peek")
    opts.add_argument("--timeout", type=int, default=5,     help="Peek timeout (default 5s)")

    args = parser.parse_args()

    if args.insecure and not args.ssl:
        parser.error("--insecure requires --ssl")
    if args.peek and not args.queue:
        parser.error("--peek requires --queue")
    if args.authority_obj and "/" not in args.authority_obj:
        parser.error("--authority-obj must be LIB/OBJ")

    manual_flags = [args.sql_query, args.rmtcmd_exec, args.ifs_path, args.authority_obj,
                    args.spool_get, args.peek]
    any_module = any([args.all, args.pwlevel, args.pwdaudit, args.audit, args.sysvals,
                      args.services, args.ddm, args.netserver, args.users, args.privusers,
                      args.groups, args.functionusage, args.authority, args.dtaq, args.spool,
                      args.savf, args.exitpoints, args.scheduler, args.ifs, args.sql,
                      args.rmtcmd, args.defcreds])
    if not any_module and not any(manual_flags):
        parser.error("Specify at least one module (e.g. --all) or a manual override (e.g. --sql-query)")
    return args


def _load_creds_file(path):
    creds = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue
            u, p = line.split(":", 1)
            creds.append((u.strip(), p.strip()))
    return creds


def main():
    print(BANNER)
    args = parse_args()

    start_jvm(args.jar)
    if args.ssl and args.insecure:
        install_trust_all_ssl()

    try:
        as400 = get_as400_connection(args.server, args.user, args.password, use_ssl=args.ssl)
    except Exception as e:
        fail(f"Authentication failed: {e}")
        sys.exit(1)

    needs_jdbc = any([
        args.all, args.sql, args.sql_query, args.users, args.privusers, args.groups,
        args.functionusage, args.netserver, args.exitpoints, args.scheduler,
        args.spool, args.sysvals, args.pwdaudit,
    ])
    conn = get_jdbc_connection(args.server, args.user, args.password,
                               use_ssl=args.ssl) if needs_jdbc else None

    qmaxsign = None
    if args.defcreds:
        try:
            from com.ibm.as400.access import SystemValue
            qmaxsign = int(str(SystemValue(as400, "QMAXSIGN").getValue()))
            info(f"QMAXSIGN = {qmaxsign}")
        except Exception:
            warn("Could not read QMAXSIGN — using conservative default of 3")

    try:
        # Posture / system
        if args.pwlevel or args.all:    enum_password_level(as400)
        if args.pwdaudit or args.all:   enum_password_audit(as400, conn)
        if args.audit or args.all:      enum_audit_posture(as400)
        if args.sysvals or args.all:    enum_sysvals(conn)

        # Network
        if args.services or args.all:   enum_services(as400, args.server, use_ssl=args.ssl)
        if args.ddm or args.all:        enum_ddm(args.server)
        if args.netserver or args.all:  enum_netserver(args.server, conn)

        # Identity / authority
        if args.users or args.all:      enum_users(conn, only_privileged=False)
        if args.privusers:              enum_users(conn, only_privileged=True)
        if args.groups or args.all:     enum_groups(conn)
        if args.functionusage or args.all: enum_function_usage(conn)

        if args.authority_obj:
            lib, obj = args.authority_obj.split("/", 1)
            enum_object_authority(as400, [(lib.upper(), obj.upper(), args.authority_type.upper())])
        elif args.authority or args.all:
            enum_object_authority(as400, DEFAULT_SENSITIVE_OBJECTS)

        # Objects / data
        if args.dtaq or args.all:       enum_data_queues(as400, args.lib)
        if args.peek:                   peek_data_queue(as400, args.lib[0], args.queue, args.timeout)
        if args.savf or args.all:       enum_savfs(as400, args.lib)
        if args.spool or args.all:      enum_spool(conn, user_filter=args.spool_user)
        if args.spool_get:              spool_get(as400, args.spool_get)
        if args.exitpoints or args.all: enum_exit_points(conn)
        if args.scheduler or args.all:  enum_scheduler(conn)

        # Filesystem
        if args.ifs_path:
            enum_ifs(as400, args.ifs_path, depth=args.ifs_depth)
        elif args.ifs or args.all:
            enum_ifs(as400, DEFAULT_IFS_PATHS, depth=args.ifs_depth)

        # Database
        if args.sql or args.all:        enum_sql(conn)
        if args.sql_query:              run_custom_sql(conn, args.sql_query)

        # Execution
        if args.rmtcmd or args.all:     enum_rmtcmd(as400, custom_cmd=None)
        if args.rmtcmd_exec:            enum_rmtcmd(as400, custom_cmd=args.rmtcmd_exec)

        # Credential testing (opt-in only, never in --all)
        if args.defcreds:
            creds = _load_creds_file(args.defcreds_file) if args.defcreds_file else DEFAULT_CREDS[:]
            source = args.defcreds_file if args.defcreds_file else "built-in default list"
            if confirm_defcreds_risk(
                cred_count=len(creds),
                qmaxsign=qmaxsign,
                aggressive=args.defcreds_aggressive,
                acknowledged=args.defcreds_acknowledge,
                creds_source=source,
            ):
                enum_default_creds(args.server, args.ssl, qmaxsign=qmaxsign,
                                   creds=creds, aggressive=args.defcreds_aggressive)

    finally:
        header("CLEANUP")
        try:
            if conn is not None:
                conn.close()
                ok("JDBC closed")
        except Exception:
            pass
        try:
            as400.disconnectAllServices()
            ok("All JT400 services disconnected")
        except Exception:
            pass
        info("Done.")


if __name__ == "__main__":
    main()
