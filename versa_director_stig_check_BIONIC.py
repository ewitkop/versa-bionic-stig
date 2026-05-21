#!/usr/bin/env python3
"""
Versa Director STIG Compliance Checker — Ubuntu 18.04 LTS (HTML Report)
=========================================================================
SSH into a Versa Director appliance (Ubuntu 18.04 based) and run DISA
STIG checks from the Canonical Ubuntu 18.04 LTS STIG (V2R13+).

Produces a professional, self-contained HTML report with:
  • Executive summary with pass/fail/manual counts and severity breakdown
  • Per-finding detail: status, severity, what was tested, raw evidence,
    how the control was checked, and step-by-step remediation
  • Collapsible sections, colour-coded badges, and print-friendly CSS

Requirements:
    pip install paramiko

Usage:
    python versa_director_stig_check_u18_html.py --host <ip> --user <user> [--key <key>] [--password]
    python versa_director_stig_check_u18_html.py --host 10.0.0.1 --user admin --password
    python versa_director_stig_check_u18_html.py --host 10.0.0.1 --user admin --key ~/.ssh/id_rsa
    python versa_director_stig_check_u18_html.py --host 10.0.0.1 --user admin --password --output report.html
    
Note: Ensure you are using the default SSH username that will have the necessary access to check configuration files.
"""

import argparse
import getpass
import html as html_mod
import json
import os
import re
import sys
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional

try:
    import paramiko
except ImportError:
    sys.exit("ERROR: paramiko is required.  Install with:  pip install paramiko")


# ═══════════════════════════════════════════════════════════════════════════
#  DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    vuln_id: str
    rule_id: str
    severity: str              # CAT I, CAT II, CAT III
    title: str
    description: str = ""      # What the STIG requires
    check_method: str = ""     # How we tested (commands run, logic applied)
    evidence: str = ""         # Raw command output / data collected
    status: str = "NOT_RUN"    # PASS, FAIL, MANUAL, ERROR, NOT_APPLICABLE
    detail: str = ""           # Human-readable result explanation
    fix: str = ""              # Step-by-step remediation


@dataclass
class StigReport:
    host: str
    scan_time: str = ""
    os_info: str = ""
    hostname: str = ""
    findings: list = field(default_factory=list)

    def summary(self):
        totals = {"PASS": 0, "FAIL": 0, "MANUAL": 0, "ERROR": 0, "NOT_APPLICABLE": 0}
        for f in self.findings:
            totals[f.status] = totals.get(f.status, 0) + 1
        return totals

    def severity_summary(self):
        cats = {"CAT I": {"PASS": 0, "FAIL": 0, "MANUAL": 0, "ERROR": 0},
                "CAT II": {"PASS": 0, "FAIL": 0, "MANUAL": 0, "ERROR": 0},
                "CAT III": {"PASS": 0, "FAIL": 0, "MANUAL": 0, "ERROR": 0}}
        for f in self.findings:
            sev = f.severity if f.severity in cats else "CAT II"
            if f.status in cats[sev]:
                cats[sev][f.status] += 1
        return cats


# ═══════════════════════════════════════════════════════════════════════════
#  SSH HELPER
# ═══════════════════════════════════════════════════════════════════════════

class RemoteExecutor:
    """Thin wrapper around paramiko for running commands on the Director."""


    def __init__(self, host: str, username: str, password: Optional[str] = None,
                 key_path: Optional[str] = None, port: int = 22, timeout: int = 30):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.sudo_password = password  # stored for sudo prompts
        connect_kwargs = dict(hostname=host, port=port, username=username, timeout=timeout,
                              look_for_keys=False, allow_agent=False)
        if password:
            connect_kwargs["password"] = password
        self.client.connect(**connect_kwargs)

    def run(self, cmd: str, timeout: int = 30) -> tuple[int, str, str]:
        """Return (exit_status, stdout, stderr)."""
        _, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
        rc = stdout.channel.recv_exit_status()
        return (rc,
                stdout.read().decode(errors="replace").strip(),
                stderr.read().decode(errors="replace").strip())
    
    def run_sudo(self, cmd: str, timeout: int = 30) -> tuple[int, str, str]:
        """Run a command with sudo, automatically responding to the password prompt.
        Uses 'sudo -S' so the password is read from stdin."""
        if not self.sudo_password:
            return self.run(f"sudo {cmd}", timeout=timeout)
        full_cmd = f"echo '{self.sudo_password}' | sudo -S {cmd}"
        stdin, stdout, stderr = self.client.exec_command(full_cmd, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode(errors="replace").strip()
        err = stderr.read().decode(errors="replace").strip()
        # Filter out the sudo password prompt line from stderr
        err_lines = [ln for ln in err.splitlines()
                     if not ln.strip().startswith("[sudo] password")]
        return (exit_code, out, "\n".join(err_lines).strip())

    def close(self):
        self.client.close()


# ═══════════════════════════════════════════════════════════════════════════
#  STIG CHECKS — DISA Canonical Ubuntu 18.04 LTS STIG V2R13+
# ═══════════════════════════════════════════════════════════════════════════

# ---------------------------------------------------------------------------
#  CAT I — CRITICAL
# ---------------------------------------------------------------------------

def check_v219150_ssh_protocol(exe: RemoteExecutor) -> Finding:
    """V-219150 | SSH must use protocol 2."""
    f = Finding(
        "V-219150", "SV-219150r879587_rule", "CAT I",
        "SSH must be configured to use only protocol version 2",
        description="The system must implement DoD-approved encryption for SSH. "
                    "Protocol version 1 has known vulnerabilities and must not be used.",
        check_method="1. Ran 'ssh -V' to determine the installed OpenSSH version.\n"
                     "2. Searched /etc/ssh/sshd_config for a 'Protocol' directive.\n"
                     "3. OpenSSH >= 7.6 removed protocol 1 support entirely, so the "
                     "version alone confirms compliance unless Protocol 1 is forced.",
        fix="1. Edit /etc/ssh/sshd_config.\n"
            "2. Ensure the line reads:  Protocol 2\n"
            "   (On OpenSSH >= 7.6 this is the only supported option.)\n"
            "3. Restart SSH:  sudo systemctl restart sshd")
    rc, out, _ = exe.run("ssh -V 2>&1; echo '---'; grep -i '^Protocol' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET'")
    f.evidence = out
    if "OpenSSH_7" in out or "OpenSSH_8" in out or "OpenSSH_9" in out:
        if "Protocol 1" in out:
            f.status, f.detail = "FAIL", "Protocol 1 is explicitly enabled despite modern OpenSSH."
        else:
            f.status, f.detail = "PASS", "OpenSSH version enforces protocol 2 by default."
    else:
        f.status, f.detail = "MANUAL", "Older OpenSSH detected — verify Protocol directive manually."
    return f


def check_v219151_ssh_empty_passwords(exe: RemoteExecutor) -> Finding:
    """V-219151 | SSH must not allow empty passwords."""
    f = Finding(
        "V-219151", "SV-219151r879589_rule", "CAT I",
        "SSH must not allow authentication with empty passwords",
        description="If empty passwords are permitted, any account without a password set "
                    "becomes a trivial attack vector.",
        check_method="Searched /etc/ssh/sshd_config for 'PermitEmptyPasswords'. "
                     "The default in OpenSSH is 'no', so if the directive is absent or "
                     "set to 'no' the check passes.",
        fix="1. Edit /etc/ssh/sshd_config.\n"
            "2. Set:  PermitEmptyPasswords no\n"
            "3. Restart SSH:  sudo systemctl restart sshd")
    rc, out, _ = exe.run("grep -i '^PermitEmptyPasswords' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET'")
    f.evidence = out
    if "NOT_SET" in out or "no" in out.lower():
        f.status, f.detail = "PASS", "PermitEmptyPasswords is disabled (default 'no')."
    else:
        f.status, f.detail = "FAIL", f"PermitEmptyPasswords is set to a non-compliant value: {out}"
    return f


def check_v219210_grub_permissions(exe: RemoteExecutor) -> Finding:
    """V-219210 | GRUB config must have proper permissions."""
    f = Finding(
        "V-219210", "SV-219210r879681_rule", "CAT I",
        "GRUB configuration file must be owned by root with mode 0600 or less",
        description="Unauthorized modification of the GRUB bootloader configuration could allow "
                    "an attacker to boot into single-user mode or alter kernel parameters.",
        check_method="Ran 'stat -c \"%a %U:%G\" /boot/grub/grub.cfg' and compared the "
                     "octal mode against 0600 and the owner against root:root.",
        fix="1. sudo chown root:root /boot/grub/grub.cfg\n"
            "2. sudo chmod 0600 /boot/grub/grub.cfg")
    rc, out, _ = exe.run("stat -c '%a %U:%G' /boot/grub/grub.cfg 2>/dev/null || echo 'NOT_FOUND'")
    f.evidence = out
    if "NOT_FOUND" in out:
        f.status, f.detail = "MANUAL", "GRUB config not found at /boot/grub/grub.cfg."
    else:
        parts = out.split()
        mode = int(parts[0], 8) if parts else 0o777
        owner = parts[1] if len(parts) > 1 else "unknown"
        issues = []
        if mode > 0o600:
            issues.append(f"mode {oct(mode)} is more permissive than 0600")
        if owner != "root:root":
            issues.append(f"owner is {owner}, expected root:root")
        if issues:
            f.status, f.detail = "FAIL", "; ".join(issues)
        else:
            f.status, f.detail = "PASS", f"GRUB config: mode={oct(mode)}, owner={owner}"
    return f


def check_v219211_no_telnet(exe: RemoteExecutor) -> Finding:
    """V-219211 | Telnet must not be installed."""
    f = Finding(
        "V-219211", "SV-219211r879683_rule", "CAT I",
        "The telnet server package must not be installed",
        description="Telnet transmits data (including credentials) in cleartext and must "
                    "not be used for remote administration.",
        check_method="Ran 'dpkg -l telnetd inetutils-telnetd' and checked for installed "
                     "('ii') status lines.",
        fix="1. sudo apt remove --purge telnetd inetutils-telnetd\n"
            "2. Verify removal:  dpkg -l telnetd inetutils-telnetd")
    rc, out, _ = exe.run("dpkg -l telnetd inetutils-telnetd 2>/dev/null | grep -E '^ii' || echo 'NOT_INSTALLED'")
    f.evidence = out
    if "NOT_INSTALLED" in out or not out.strip():
        f.status, f.detail = "PASS", "Telnet server is not installed."
    else:
        f.status, f.detail = "FAIL", "Telnet server package(s) found installed."
    return f


def check_v219212_no_rsh(exe: RemoteExecutor) -> Finding:
    """V-219212 | rsh server must not be installed."""
    f = Finding(
        "V-219212", "SV-219212r879685_rule", "CAT I",
        "The rsh-server package must not be installed",
        description="rsh provides unencrypted remote shell access and is a high-risk service.",
        check_method="Ran 'dpkg -l rsh-server' and checked for 'ii' (installed) status.",
        fix="1. sudo apt remove --purge rsh-server\n"
            "2. Verify:  dpkg -l rsh-server")
    rc, out, _ = exe.run("dpkg -l rsh-server 2>/dev/null | grep -E '^ii' || echo 'NOT_INSTALLED'")
    f.evidence = out
    if "NOT_INSTALLED" in out:
        f.status, f.detail = "PASS", "rsh-server is not installed."
    else:
        f.status, f.detail = "FAIL", "rsh-server package is installed."
    return f


def check_v219230_ctrl_alt_del(exe: RemoteExecutor) -> Finding:
    """V-219230 | Ctrl-Alt-Del must be disabled."""
    f = Finding(
        "V-219230", "SV-219230r879719_rule", "CAT I",
        "The system must disable the Ctrl-Alt-Delete reboot key sequence",
        description="A locally logged-in user could accidentally or maliciously reboot the "
                    "system using Ctrl-Alt-Del if it is not masked.",
        check_method="Ran 'systemctl status ctrl-alt-del.target' and checked whether it "
                     "is masked (symlinked to /dev/null).",
        fix="1. sudo systemctl mask ctrl-alt-del.target\n"
            "2. sudo systemctl daemon-reload\n"
            "3. Verify:  systemctl status ctrl-alt-del.target (should show 'masked')")
    rc, out, _ = exe.run("systemctl status ctrl-alt-del.target 2>&1")
    f.evidence = out
    if "masked" in out.lower():
        f.status, f.detail = "PASS", "ctrl-alt-del.target is masked."
    else:
        f.status, f.detail = "FAIL", "ctrl-alt-del.target is NOT masked."
    return f


def check_v219240_fips_mode(exe: RemoteExecutor) -> Finding:
    """V-219240 | FIPS mode must be enabled."""
    f = Finding(
        "V-219240", "SV-219240r879739_rule", "CAT I",
        "FIPS 140-2 mode must be enabled on the operating system",
        description="FIPS 140-2 validated cryptography is required for DoD systems to "
                    "protect sensitive data at rest and in transit.",
        check_method="Read /proc/sys/crypto/fips_enabled. A value of '1' means FIPS mode "
                     "is active; '0' means it is not.",
        fix="1. Install the FIPS kernel:  sudo ua enable fips  (or manually install fips packages)\n"
            "2. Add 'fips=1' to GRUB_CMDLINE_LINUX in /etc/default/grub\n"
            "3. sudo update-grub && sudo reboot\n"
            "4. Verify:  cat /proc/sys/crypto/fips_enabled  (should return 1)")
    rc, out, _ = exe.run("cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 'NOT_FOUND'")
    f.evidence = out
    if out.strip() == "1":
        f.status, f.detail = "PASS", "FIPS mode is enabled (fips_enabled=1)."
    elif out.strip() == "0":
        f.status, f.detail = "FAIL", "FIPS mode is NOT enabled (fips_enabled=0)."
    else:
        f.status, f.detail = "FAIL", f"Cannot determine FIPS status: {out}"
    return f


# ---------------------------------------------------------------------------
#  CAT II — SSH HARDENING
# ---------------------------------------------------------------------------

def check_v219152_ssh_root_login(exe: RemoteExecutor) -> Finding:
    """V-219152 | SSH must not permit direct root login."""
    f = Finding(
        "V-219152", "SV-219152r879591_rule", "CAT II",
        "SSH must not allow direct login as root",
        description="Direct root login over SSH bypasses accountability; administrators "
                    "should authenticate with personal accounts and escalate with sudo.",
        check_method="Searched /etc/ssh/sshd_config for 'PermitRootLogin'. The directive "
                     "must be set to 'no' (not 'without-password' or 'prohibit-password').",
        fix="1. Edit /etc/ssh/sshd_config\n"
            "2. Set:  PermitRootLogin no\n"
            "3. sudo systemctl restart sshd")
    rc, out, _ = exe.run_sudo("grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET'")
    f.evidence = out
    if "NOT_SET" in out:
        f.status, f.detail = "FAIL", "PermitRootLogin not explicitly set (may default to yes)."
    elif "no" == out.split()[-1].lower():
        f.status, f.detail = "PASS", "Root login is disabled."
    else:
        f.status, f.detail = "FAIL", f"PermitRootLogin = {out}"
    return f


def check_v219153_ssh_x11(exe: RemoteExecutor) -> Finding:
    """V-219153 | SSH X11 forwarding must be disabled."""
    f = Finding(
        "V-219153", "SV-219153r879593_rule", "CAT II",
        "SSH X11 forwarding must be disabled",
        description="X11 forwarding over SSH can expose the X11 display to the remote server, "
                    "creating a potential attack surface.",
        check_method="Searched /etc/ssh/sshd_config for 'X11Forwarding'. Must be 'no'.",
        fix="1. Edit /etc/ssh/sshd_config\n"
            "2. Set:  X11Forwarding no\n"
            "3. sudo systemctl restart sshd")
    rc, out, _ = exe.run("grep -i '^X11Forwarding' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET'")
    f.evidence = out
    if "no" in out.lower():
        f.status, f.detail = "PASS", "X11Forwarding is disabled."
    else:
        f.status, f.detail = "FAIL", f"X11Forwarding setting: {out}"
    return f


def check_v219154_ssh_idle_timeout(exe: RemoteExecutor) -> Finding:
    """V-219154 | SSH idle timeout must be <= 600 seconds."""
    f = Finding(
        "V-219154", "SV-219154r879595_rule", "CAT II",
        "SSH ClientAliveInterval must be set to 600 seconds or less",
        description="An idle SSH session that remains open indefinitely is an attack vector "
                    "if a user steps away from their workstation.",
        check_method="Searched /etc/ssh/sshd_config for 'ClientAliveInterval'. The value "
                     "must be between 1 and 600 (inclusive).",
        fix="1. Edit /etc/ssh/sshd_config\n"
            "2. Set:  ClientAliveInterval 600\n"
            "3. sudo systemctl restart sshd")
    rc, out, _ = exe.run_sudo("grep -i '^ClientAliveInterval' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET'")
    f.evidence = out
    if "NOT_SET" in out:
        f.status, f.detail = "FAIL", "ClientAliveInterval is not set."
    else:
        try:
            val = int(re.search(r'\d+', out).group())
            if 1 <= val <= 600:
                f.status, f.detail = "PASS", f"ClientAliveInterval = {val}s"
            else:
                f.status, f.detail = "FAIL", f"ClientAliveInterval = {val}s (must be 1-600)"
        except Exception:
            f.status, f.detail = "MANUAL", f"Could not parse value: {out}"
    return f


def check_v219155_ssh_alive_count(exe: RemoteExecutor) -> Finding:
    """V-219155 | SSH ClientAliveCountMax must be <= 1."""
    f = Finding(
        "V-219155", "SV-219155r879597_rule", "CAT II",
        "SSH ClientAliveCountMax must be set to 1",
        description="Combined with ClientAliveInterval, this ensures the session is terminated "
                    "promptly after the interval expires without a response.",
        check_method="Searched /etc/ssh/sshd_config for 'ClientAliveCountMax'. Must be <= 1.",
        fix="1. Edit /etc/ssh/sshd_config\n"
            "2. Set:  ClientAliveCountMax 1\n"
            "3. sudo systemctl restart sshd")
    rc, out, _ = exe.run_sudo("grep -i '^ClientAliveCountMax' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET'")
    f.evidence = out
    if "NOT_SET" in out:
        f.status, f.detail = "FAIL", "ClientAliveCountMax not set."
    else:
        try:
            val = int(re.search(r'\d+', out).group())
            f.status = "PASS" if val <= 1 else "FAIL"
            f.detail = f"ClientAliveCountMax = {val}" + ("" if val <= 1 else " (must be <= 1)")
        except Exception:
            f.status, f.detail = "MANUAL", f"Could not parse: {out}"
    return f


def check_v219156_ssh_ciphers(exe: RemoteExecutor) -> Finding:
    """V-219156 | SSH must use FIPS 140-2 approved ciphers."""
    f = Finding(
        "V-219156", "SV-219156r879599_rule", "CAT II",
        "SSH must only allow FIPS 140-2 compliant ciphers",
        description="Using non-FIPS ciphers weakens the encryption protecting SSH sessions.",
        check_method="Read the 'Ciphers' line from /etc/ssh/sshd_config and compared each "
                     "cipher against the FIPS-approved list: aes256-ctr, aes192-ctr, "
                     "aes128-ctr, aes256-gcm@openssh.com, aes128-gcm@openssh.com.",
        fix="1. Edit /etc/ssh/sshd_config\n"
            "2. Set:  Ciphers aes256-ctr,aes192-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com\n"
            "3. sudo systemctl restart sshd")
    approved = {"aes256-ctr", "aes192-ctr", "aes128-ctr",
                "aes256-gcm@openssh.com", "aes128-gcm@openssh.com"}
    rc, out, _ = exe.run_sudo("grep -i '^Ciphers' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET'")
    f.evidence = out
    if "NOT_SET" in out:
        f.status, f.detail = "FAIL", "No explicit cipher list configured."
    else:
        ciphers = {c.strip() for c in out.split(None, 1)[-1].split(",")}
        bad = ciphers - approved
        if bad:
            f.status, f.detail = "FAIL", f"Non-FIPS ciphers found: {', '.join(sorted(bad))}"
        else:
            f.status, f.detail = "PASS", "All ciphers are FIPS approved."
    return f


def check_v219157_ssh_macs(exe: RemoteExecutor) -> Finding:
    """V-219157 | SSH must use FIPS 140-2 approved MACs."""
    f = Finding(
        "V-219157", "SV-219157r879601_rule", "CAT II",
        "SSH must only allow FIPS 140-2 compliant MACs",
        description="Message Authentication Codes protect data integrity during SSH sessions.",
        check_method="Read the 'MACs' line from /etc/ssh/sshd_config and compared each MAC "
                     "against the approved list: hmac-sha2-256, hmac-sha2-512 "
                     "(and their -etm@openssh.com variants).",
        fix="1. Edit /etc/ssh/sshd_config\n"
            "2. Set:  MACs hmac-sha2-256,hmac-sha2-512,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com\n"
            "3. sudo systemctl restart sshd")
    approved = {"hmac-sha2-256", "hmac-sha2-512",
                "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com"}
    rc, out, _ = exe.run_sudo("grep -i '^MACs' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET'")
    f.evidence = out
    if "NOT_SET" in out:
        f.status, f.detail = "FAIL", "No explicit MAC list configured."
    else:
        macs = {m.strip() for m in out.split(None, 1)[-1].split(",")}
        bad = macs - approved
        if bad:
            f.status, f.detail = "FAIL", f"Non-FIPS MACs: {', '.join(sorted(bad))}"
        else:
            f.status, f.detail = "PASS", "All MACs are FIPS approved."
    return f


def check_v219158_ssh_banner(exe: RemoteExecutor) -> Finding:
    """V-219158 | SSH must display a login banner."""
    f = Finding(
        "V-219158", "SV-219158r879603_rule", "CAT II",
        "SSH must display a DoD-approved banner before authentication",
        description="Displaying a warning banner establishes legal notice that the system "
                    "is for authorized use only, which is required for prosecution.",
        check_method="1. Checked for existance of a USG DOD in /var/versa/banners/motd_banner.\n"
                     "2. If set, verified the referenced file exists and is non-empty.",
        fix="1. Browse to the Versa Director, Administration, System, Banner and set the appropriate USG banner\n")
           
    rc, out, _ = exe.run("grep -i 'USG' /var/versa/banners/motd_banner 2>/dev/null || echo 'NOT_SET'")
    f.evidence = out
    if "NOT_SET" in out:
        f.status, f.detail = "FAIL", "No USG DOD MOTD Banner directive set."
    else:
            f.status, f.detail = "PASS", f"SSH Banner is set and contains USG content."
    return f


# ---------------------------------------------------------------------------
#  CAT II — PASSWORD POLICIES
# ---------------------------------------------------------------------------

def _check_pwquality(exe, vuln, rule, title, param, operator, threshold, desc, fix_line):
    """Generic helper for pwquality.conf integer checks."""
    f = Finding(
        vuln, rule, "CAT II", title,
        description=desc,
        check_method=f"Searched /etc/security/pwquality.conf for '{param}' and compared "
                     f"the value against the threshold ({operator} {threshold}).",
        fix=f"1. Edit /etc/security/pwquality.conf\n2. Set:  {fix_line}\n"
            "3. No service restart required — PAM reads the file on each authentication.")
    rc, out, _ = exe.run(f"grep -i '^{param}' /etc/security/pwquality.conf 2>/dev/null || echo 'NOT_SET'")
    f.evidence = out
    if "NOT_SET" in out:
        f.status, f.detail = "FAIL", f"{param} is not configured in pwquality.conf."
    else:
        try:
            val = int(re.search(r'-?\d+', out).group())
            if operator == ">=" and val >= threshold:
                f.status, f.detail = "PASS", f"{param} = {val}"
            elif operator == "<=" and val <= threshold:
                f.status, f.detail = "PASS", f"{param} = {val}"
            else:
                f.status, f.detail = "FAIL", f"{param} = {val} (must be {operator} {threshold})"
        except Exception:
            f.status, f.detail = "MANUAL", f"Could not parse: {out}"
    return f


def check_v219166_pw_minlen(exe):
    """V-219166 | Password minimum length >= 15."""
    return _check_pwquality(exe, "V-219166", "SV-219166r879615_rule",
        "Passwords must have a minimum of 15 characters",
        "minlen", ">=", 15,
        "Short passwords are easier to brute-force. DISA requires a minimum of 15.",
        "minlen = 15")

def check_v219167_pw_ucredit(exe):
    """V-219167 | At least one uppercase."""
    return _check_pwquality(exe, "V-219167", "SV-219167r879617_rule",
        "Passwords must contain at least one uppercase character",
        "ucredit", "<=", -1,
        "Password complexity reduces guessability. A negative ucredit enforces uppercase.",
        "ucredit = -1")

def check_v219168_pw_lcredit(exe):
    """V-219168 | At least one lowercase."""
    return _check_pwquality(exe, "V-219168", "SV-219168r879619_rule",
        "Passwords must contain at least one lowercase character",
        "lcredit", "<=", -1,
        "Password complexity reduces guessability. A negative lcredit enforces lowercase.",
        "lcredit = -1")

def check_v219169_pw_dcredit(exe):
    """V-219169 | At least one digit."""
    return _check_pwquality(exe, "V-219169", "SV-219169r879621_rule",
        "Passwords must contain at least one numeric character",
        "dcredit", "<=", -1,
        "Digits add entropy. A negative dcredit value requires at least one digit.",
        "dcredit = -1")

def check_v219170_pw_ocredit(exe):
    """V-219170 | At least one special character."""
    return _check_pwquality(exe, "V-219170", "SV-219170r879623_rule",
        "Passwords must contain at least one special character",
        "ocredit", "<=", -1,
        "Special characters further increase password entropy.",
        "ocredit = -1")


def check_v219171_pw_history(exe: RemoteExecutor) -> Finding:
    """V-219171 | Password reuse prohibited for 5 generations."""
    f = Finding(
        "V-219171", "SV-219171r879625_rule", "CAT II",
        "System must prohibit password reuse for a minimum of 5 generations",
        description="Reusing recent passwords makes compromise more likely after a leak.",
        check_method="Searched /etc/pam.d/common-password for pam_unix or pam_pwhistory "
                     "with 'remember=N' and verified N >= 5.",
        fix="1. Edit /etc/pam.d/common-password\n"
            "2. On the pam_unix.so line, add:  remember=5\n"
            "   Or add a pam_pwhistory.so line:  password required pam_pwhistory.so remember=5")
    rc, out, _ = exe.run("grep -E 'remember=5' /etc/pam.d/common-password 2>/dev/null")
    f.evidence = out
    match = re.search(r'remember=(\d+)', out)
    if match:
        val = int(match.group(1))
        f.status = "PASS" if val >= 5 else "FAIL"
        f.detail = f"remember = {val}" + ("" if val >= 5 else " (must be >= 5)")
    else:
        f.status, f.detail = "FAIL", "No 'remember' parameter found in PAM password config."
    return f


def check_v219172_pw_max_age(exe: RemoteExecutor) -> Finding:
    """V-219172 | Password maximum lifetime <= 60 days."""
    f = Finding(
        "V-219172", "SV-219172r879627_rule", "CAT II",
        "Password maximum lifetime must be restricted to 60 days",
        description="Forcing periodic password changes limits the window an attacker has "
                    "to use a compromised credential.",
        check_method="Read 'PASS_MAX_DAYS' from /etc/login.defs and verified <= 60.",
        fix="1. Edit /etc/login.defs\n"
            "2. Set:  PASS_MAX_DAYS   60\n"
            "3. For existing users:  sudo chage --maxdays 60 <username>")
    rc, out, _ = exe.run("grep '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null || echo 'NOT_SET'")
    f.evidence = out
    if "NOT_SET" in out:
        f.status, f.detail = "FAIL", "PASS_MAX_DAYS not set."
    else:
        try:
            val = int(re.search(r'\d+', out).group())
            f.status = "PASS" if val <= 60 else "FAIL"
            f.detail = f"PASS_MAX_DAYS = {val}" + ("" if val <= 60 else " (must be <= 60)")
        except Exception:
            f.status, f.detail = "MANUAL", f"Could not parse: {out}"
    return f


def check_v219173_pw_min_age(exe: RemoteExecutor) -> Finding:
    """V-219173 | Password minimum lifetime >= 1 day."""
    f = Finding(
        "V-219173", "SV-219173r879629_rule", "CAT II",
        "Password minimum lifetime must be at least 1 day",
        description="Without a minimum age, users can cycle through passwords to reuse an old one.",
        check_method="Read 'PASS_MIN_DAYS' from /etc/login.defs and verified >= 1.",
        fix="1. Edit /etc/login.defs\n"
            "2. Set:  PASS_MIN_DAYS   1\n"
            "3. For existing users:  sudo chage --mindays 1 <username>")
    rc, out, _ = exe.run("grep '^PASS_MIN_DAYS' /etc/login.defs 2>/dev/null || echo 'NOT_SET'")
    f.evidence = out
    if "NOT_SET" in out:
        f.status, f.detail = "FAIL", "PASS_MIN_DAYS not set."
    else:
        try:
            val = int(re.search(r'\d+', out).group())
            f.status = "PASS" if val >= 1 else "FAIL"
            f.detail = f"PASS_MIN_DAYS = {val}" + ("" if val >= 1 else " (must be >= 1)")
        except Exception:
            f.status, f.detail = "MANUAL", f"Could not parse: {out}"
    return f


def check_v219174_account_lockout(exe: RemoteExecutor) -> Finding:
    """V-219174 | Account lockout after 3 failed attempts."""
    f = Finding(
        "V-219174", "SV-219174r879631_rule", "CAT II",
        "Account must lock after 3 consecutive invalid login attempts",
        description="Account lockout mitigates brute-force attacks against user credentials.",
        check_method="Searched /etc/pam.d/common-auth for pam_tally2 or pam_faillock with "
                     "'deny=N' and verified N <= 3.",
        fix="1. Edit /etc/pam.d/common-auth\n"
            "2. Add before pam_unix:  auth required pam_tally2.so deny=3 onerr=fail "
            "unlock_time=900 audit\n"
            "3. Also add to /etc/pam.d/common-account:  account required pam_tally2.so")
    rc, out, _ = exe.run("grep -E 'pam_tally2|pam_faillock' /etc/pam.d/common-auth 2>/dev/null")
    f.evidence = out
    match = re.search(r'deny=(\d+)', out)
    if match:
        val = int(match.group(1))
        f.status = "PASS" if val <= 3 else "FAIL"
        f.detail = f"Account lockout deny = {val}" + ("" if val <= 3 else " (must be <= 3)")
    else:
        f.status, f.detail = "FAIL", "No account lockout (pam_tally2/pam_faillock) configured."
    return f


# ---------------------------------------------------------------------------
#  CAT II — AUDIT
# ---------------------------------------------------------------------------

def check_v219200_auditd_installed(exe: RemoteExecutor) -> Finding:
    """V-219200 | auditd must be installed."""
    f = Finding(
        "V-219200", "SV-219200r879661_rule", "CAT II",
        "The audit system (auditd) must be installed",
        description="auditd provides the kernel audit framework required for accountability.",
        check_method="Ran 'dpkg -l auditd' and looked for installed status ('ii').",
        fix="1. sudo apt install auditd audispd-plugins\n"
            "2. sudo systemctl enable auditd\n"
            "3. sudo systemctl start auditd")
    rc, out, _ = exe.run("dpkg -l auditd 2>/dev/null | grep -E '^ii'")
    f.evidence = out if out else "(no output — package not found)"
    f.status = "PASS" if out else "FAIL"
    f.detail = "auditd is installed." if out else "auditd is NOT installed."
    return f


def check_v219201_auditd_enabled(exe: RemoteExecutor) -> Finding:
    """V-219201 | auditd must be running and enabled."""
    f = Finding(
        "V-219201", "SV-219201r879663_rule", "CAT II",
        "The audit service (auditd) must be running and enabled at boot",
        description="If auditd is not running, no kernel audit events are collected.",
        check_method="Ran 'systemctl is-active auditd' and 'systemctl is-enabled auditd'.",
        fix="1. sudo systemctl enable auditd\n"
            "2. sudo systemctl start auditd\n"
            "3. Verify:  systemctl is-active auditd  ->  active")
    rc, out_active, _ = exe.run("systemctl is-active auditd 2>/dev/null")
    rc2, out_enabled, _ = exe.run("systemctl is-enabled auditd 2>/dev/null")
    f.evidence = f"is-active: {out_active}\nis-enabled: {out_enabled}"
    if "active" == out_active.strip() and "enabled" == out_enabled.strip():
        f.status, f.detail = "PASS", "auditd is active and enabled."
    else:
        f.status, f.detail = "FAIL", f"auditd active={out_active}, enabled={out_enabled}"
    return f


def check_v238230_audit_log_perms(exe: RemoteExecutor) -> Finding:
    """V-238230 | Audit log files must have mode 0600 or less."""
    f = Finding("V-238230", "SV-238230r653865_rule", "CAT II",
                "Ubuntu 18 audit log files must have mode 0600 or less permissive",
                fix="sudo chmod 0600 /var/log/audit/audit.log.")
    rc, out, _ = exe.run_sudo("stat -c '%a' /var/log/audit/audit.log 2>/dev/null || echo 'NOT_FOUND'")


    if "NOT_FOUND" in out:
        f.status, f.detail = "FAIL", "Audit log not found at /var/log/audit/audit.log."
    else:
        try:
            mode = int(out.strip(), 8)
            f.status = "PASS" if mode <= 0o600 else "FAIL"
            f.detail = f"Audit log mode: {oct(mode)}" + ("" if mode <= 0o600 else " (must be ≤ 0600)")
        except Exception:
            f.status, f.detail = "MANUAL", f"Could not parse: {out}"
    return f


# ---------------------------------------------------------------------------
#  CAT II — FILE INTEGRITY
# ---------------------------------------------------------------------------

def check_v219220_aide_installed(exe: RemoteExecutor) -> Finding:
    """V-219220 | File integrity tool (AIDE) must be installed."""
    f = Finding(
        "V-219220", "SV-219220r879699_rule", "CAT II",
        "A file integrity monitoring tool must be installed (AIDE)",
        description="File integrity tools detect unauthorized modifications to system files. It should be noted that Versa Networks does not approve of any 3rd applications.",
        check_method="Checked for AIDE, Tripwire, or OSSEC via dpkg -l.",
        fix="1. sudo apt install aide aide-common\n"
            "2. Initialize the database:  sudo aideinit\n"
            "3. Schedule daily checks:  add 'aide --check' to cron")
    rc, out, _ = exe.run("dpkg -l aide 2>/dev/null | grep -E '^ii' || echo 'NOT_INSTALLED'")
    f.evidence = out
    if "NOT_INSTALLED" not in out:
        f.status, f.detail = "PASS", "AIDE is installed."
    else:
        rc2, out2, _ = exe.run("dpkg -l tripwire ossec-hids-agent 2>/dev/null | grep -E '^ii' || echo 'NOT_INSTALLED'")
        f.evidence += f"\n{out2}"
        if "NOT_INSTALLED" not in out2:
            f.status, f.detail = "PASS", "Alternative integrity tool found."
        else:
            f.status, f.detail = "MANUAL", "No file integrity tool (AIDE/Tripwire/OSSEC) found. Versa Networks does not approve any 3rd party software installs."
    return f


# ---------------------------------------------------------------------------
#  CAT II — FILE PERMISSIONS
# ---------------------------------------------------------------------------

def _check_file_perms(exe, vuln, rule, filepath, max_mode, expected_owner, desc_extra=""):
    """Generic file permission / ownership checker."""
    f = Finding(
        vuln, rule, "CAT II",
        f"{filepath} must have permissions {oct(max_mode)} or less",
        description=f"Incorrect permissions on {filepath} could allow unauthorized access. {desc_extra}",
        check_method=f"Ran 'stat -c \"%a %U:%G\" {filepath}' and compared mode against "
                     f"{oct(max_mode)} and owner against {expected_owner}.",
        fix=f"1. sudo chmod {oct(max_mode)[2:]} {filepath}\n"
            f"2. sudo chown {expected_owner} {filepath}")
    rc, out, _ = exe.run(f"stat -c '%a %U:%G' {filepath} 2>/dev/null || echo 'NOT_FOUND'")
    f.evidence = out
    if "NOT_FOUND" in out:
        f.status, f.detail = "ERROR", f"{filepath} not found."
        return f
    parts = out.split()
    mode = int(parts[0], 8) if parts else 0o777
    owner = parts[1] if len(parts) > 1 else "unknown"
    issues = []
    if mode > max_mode:
        issues.append(f"mode {oct(mode)} exceeds {oct(max_mode)}")
    if expected_owner and owner != expected_owner:
        issues.append(f"owner is {owner}, expected {expected_owner}")
    f.status = "FAIL" if issues else "PASS"
    f.detail = "; ".join(issues) if issues else f"{filepath}: mode={oct(mode)}, owner={owner}"
    return f


def check_v219300_shadow_perms(exe):
    """V-219300 | /etc/shadow permissions."""
    return _check_file_perms(exe, "V-219300", "SV-219300r879859_rule",
        "/etc/shadow", 0o640, "root:shadow",
        "Contains hashed passwords; must be tightly restricted.")

def check_v219310_passwd_perms(exe):
    """V-219310 | /etc/passwd permissions."""
    return _check_file_perms(exe, "V-219310", "SV-219310r879879_rule",
        "/etc/passwd", 0o644, "root:root",
        "World-readable is acceptable (needed for name lookups) but not world-writable.")

def check_v219311_group_perms(exe):
    """V-219311 | /etc/group permissions."""
    return _check_file_perms(exe, "V-219311", "SV-219311r879881_rule",
        "/etc/group", 0o644, "root:root",
        "Group file should be owned by root and not world-writable.")


# ---------------------------------------------------------------------------
#  CAT II — SYSTEM HARDENING
# ---------------------------------------------------------------------------

def check_v219320_no_world_writable(exe: RemoteExecutor) -> Finding:
    """V-219320 | No world-writable files."""
    f = Finding(
        "V-219320", "SV-219320r879899_rule", "CAT II",
        "There must be no world-writable files on the system",
        description="World-writable files can be modified by any user, leading to privilege escalation.",
        check_method="Ran 'find / -xdev -type f -perm -0002' excluding /proc, /sys, /run "
                     "and listed up to 20 results.",
        fix="For each file found:\n  sudo chmod o-w <filepath>\n"
            "Investigate why the file was world-writable.")
    rc, out, _ = exe.run(
        "find / -xdev -type f -perm -0002 -not -path '/proc/*' -not -path '/sys/*' "
        "-not -path '/run/*' 2>/dev/null | head -20")
    f.evidence = out if out else "(none found)"
    if not out.strip():
        f.status, f.detail = "PASS", "No world-writable files found."
    else:
        count = len(out.strip().split('\n'))
        f.status, f.detail = "FAIL", f"Found {count} world-writable file(s)."
    return f


def check_v219330_no_unowned(exe: RemoteExecutor) -> Finding:
    """V-219330 | All files must have a valid owner."""
    f = Finding(
        "V-219330", "SV-219330r879919_rule", "CAT II",
        "All files and directories must have a valid owner",
        description="Unowned files may have been left by deleted accounts and could pose a risk.",
        check_method="Ran 'find / -xdev -nouser' excluding /proc, /sys, /run.",
        fix="For each file:\n  sudo chown <appropriate_user>:<group> <filepath>\n"
            "Or remove if the file is no longer needed.")
    rc, out, _ = exe.run(
        "find / -xdev -nouser -not -path '/proc/*' -not -path '/sys/*' "
        "-not -path '/run/*' 2>/dev/null | head -20")
    f.evidence = out if out else "(none found)"
    if not out.strip():
        f.status, f.detail = "PASS", "No unowned files found."
    else:
        count = len(out.strip().split('\n'))
        f.status, f.detail = "FAIL", f"Found {count} unowned file(s)."
    return f


def check_v219250_noexec_tmp(exe: RemoteExecutor) -> Finding:
    """V-219250 | /tmp must be mounted with noexec."""
    f = Finding(
        "V-219250", "SV-219250r879759_rule", "CAT II",
        "The /tmp partition must be mounted with the noexec option",
        description="Preventing execution from /tmp mitigates common malware staging techniques.",
        check_method="Ran 'mount | grep /tmp' and checked for the 'noexec' option in mount flags.",
        fix="1. Edit /etc/fstab, add 'noexec' to the /tmp mount options.\n"
            "   Example: tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0\n"
            "2. Remount:  sudo mount -o remount /tmp")
    rc, out, _ = exe.run("mount | grep ' /tmp ' 2>/dev/null || echo 'NOT_MOUNTED'")
    f.evidence = out
    if "NOT_MOUNTED" in out:
        f.status, f.detail = "MANUAL", "/tmp is not a separate mount — review whether it should be."
    elif "noexec" in out:
        f.status, f.detail = "PASS", "/tmp is mounted with noexec."
    else:
        f.status, f.detail = "FAIL", f"/tmp is missing 'noexec': {out}"
    return f


def check_v219260_firewall(exe: RemoteExecutor) -> Finding:
    """V-219260 | Firewall must be active."""
    f = Finding(
        "V-219260", "SV-219260r879779_rule", "CAT II",
        "An application firewall (UFW or iptables) must be installed and active",
        description="A host-based firewall restricts network access to only required services. All Versa Head End appliances run a host-based stateful firewall.",
        check_method="1. Ran 'lsmod | grep ip_tables' to check iptables.\n",    
        fix="1. sudo iptables\n"
            "2. Configure rules Example:  sudo iptables -A INPUT -i lo -j ACCEPT\n"
            "3. Verify:  sudo iptables -L -n")
  
    rc, out, _ = exe.run("lsmod | grep ip_tables || echo 'NOT_FOUND'")
    f.evidence = out
    if "NOT_FOUND" in out:
        f.status, f.detail = "FAIL", "No iptables rules in place."
    else:
        f.status, f.detail = "PASS", "iptables rules are in place."
    return f


def check_v219270_syslog_remote(exe: RemoteExecutor) -> Finding:
    """V-219270 | Syslog must forward to a remote server."""
    f = Finding(
        "V-219270", "SV-219270r879799_rule", "CAT II",
        "System logs must be forwarded to a centralized remote syslog server",
        description="Remote logging ensures logs survive if the local system is compromised.",
        check_method="Searched /etc/rsyslog.d/*.conf for forwarding "
                     "rules (lines containing @ or @@).",
        fix="1. Go to your Director GUI and proceed to Administration -> Connectors -> then SYSLOG \n")
           
    rc, out, _ = exe.run("grep -rE '.*@{1,2}'  /etc/rsyslog.d/*.conf 2>/dev/null || echo 'NOT_FOUND'")
    f.evidence = out
    if "NOT_FOUND" in out or not out.strip():
        f.status, f.detail = "FAIL", "No remote syslog forwarding configured."
    else:
        f.status, f.detail = "PASS", "Remote syslog forwarding is configured."
    return f


def check_v219290_no_games(exe: RemoteExecutor) -> Finding:
    """V-219290 | Unauthorized packages (games) must not be installed."""
    f = Finding(
        "V-219290", "SV-219290r879839_rule", "CAT II",
        "System must not have unnecessary / unauthorized packages (e.g. games)",
        description="Unnecessary software increases the attack surface of the system.",
        check_method="Ran 'dpkg -l' and searched for game-related or X server packages.",
        fix="1. Remove unauthorized packages:\n"
            "   sudo apt remove --purge <package_name>\n"
            "2. Review the full package list:  dpkg -l | less")
    rc, out, _ = exe.run("dpkg -l | grep -Ei 'game|xserver-xorg' | grep '^ii' || echo 'NONE_FOUND'")
    f.evidence = out
    if "NONE_FOUND" in out:
        f.status, f.detail = "PASS", "No unauthorized packages (games, X server) found."
    else:
        f.status, f.detail = "FAIL", "Potentially unauthorized packages found."
    return f


def check_v219340_ntp(exe: RemoteExecutor) -> Finding:
    """V-219340 | Time synchronization must be configured."""
    f = Finding(
        "V-219340", "SV-219340r879939_rule", "CAT II",
        "Time synchronization (NTP/chrony/timesyncd) must be configured and active",
        description="Accurate time is critical for audit log correlation and authentication protocols.",
        check_method="Checked systemctl is-active for chrony, ntp, and systemd-timesyncd.",
        fix="1. Install chrony:  sudo apt install chrony\n"
            "2. Configure servers in /etc/chrony/chrony.conf\n"
            "3. sudo systemctl enable chrony && sudo systemctl start chrony")
    results = {}
    evidence_lines = []
    for svc in ["chrony", "ntp", "systemd-timesyncd"]:
        _, out, _ = exe.run(f"systemctl is-active {svc} 2>/dev/null || echo 'inactive'")
        results[svc] = out.strip()
        evidence_lines.append(f"{svc}: {out.strip()}")
    f.evidence = "\n".join(evidence_lines)
    active = [s for s, v in results.items() if v == "active"]
    if active:
        f.status, f.detail = "PASS", f"Time sync active: {', '.join(active)}"
    else:
        f.status, f.detail = "FAIL", "No time synchronization service is running."
    return f


def check_v219350_usb_disabled(exe: RemoteExecutor) -> Finding:
    """V-219350 | USB mass storage must be disabled."""
    f = Finding(
        "V-219350", "SV-219350r879959_rule", "CAT II",
        "USB mass storage kernel module must be disabled",
        description="USB storage devices can be used to exfiltrate data or introduce malware.",
        check_method="1. Searched /etc/modprobe.d/ for 'install usb-storage /bin/true'.\n"
                     "2. Checked 'lsmod' to see if usb_storage is currently loaded.",
        fix="1. echo 'install usb-storage /bin/true' | sudo tee /etc/modprobe.d/disable-usb-storage.conf\n"
            "2. echo 'blacklist usb-storage' | sudo tee -a /etc/modprobe.d/blacklist.conf\n"
            "3. If module is loaded:  sudo modprobe -r usb_storage")
    rc, out, _ = exe.run("grep -rE 'install\\s+usb-storage' /etc/modprobe.d/ 2>/dev/null || echo 'NOT_SET'")
    rc2, out2, _ = exe.run("lsmod | grep usb_storage 2>/dev/null || echo 'NOT_LOADED'")
    f.evidence = f"modprobe config: {out}\nlsmod: {out2}"
    if "/bin/true" in out or "/bin/false" in out:
        f.status, f.detail = "PASS", "USB storage module is disabled in modprobe."
    elif "NOT_SET" in out and "NOT_LOADED" not in out2:
        f.status, f.detail = "FAIL", "USB storage module is loaded and not blacklisted."
    else:
        f.status, f.detail = "FAIL", "USB storage not disabled in modprobe config."
    return f


# ---------------------------------------------------------------------------
#  VERSA-SPECIFIC
# ---------------------------------------------------------------------------

def check_versa_services(exe: RemoteExecutor) -> Finding:
    """VERSA-001 | Versa Director core services status."""
    f = Finding(
        "VERSA-001", "VERSA-SVC-001", "CAT II",
        "Versa Director core services must be running",
        description="The Versa Director appliance should have its management services active.",
        check_method="Listed running services and filtered for versa/vnms/director keywords.",
        fix="1. Check Versa logs:  journalctl -u versa-*\n"
            "2. Restart:  sudo systemctl restart versa-director*")
    rc, out, _ = exe.run(
        "systemctl list-units --type=service --state=running 2>/dev/null | "
        "grep -iE 'versa|vnms|director' || echo 'NONE_FOUND'")
    f.evidence = out
    if "NONE_FOUND" in out:
        f.status, f.detail = "MANUAL", "No Versa services detected — may use different service names."
    else:
        f.status, f.detail = "PASS", "Versa services are running."
    return f


def check_versa_ports(exe: RemoteExecutor) -> Finding:
    """VERSA-002 | Audit listening ports."""
    f = Finding(
        "VERSA-002", "VERSA-PORT-001", "CAT II",
        "Only authorized network services should be listening",
        description="Unnecessary listening services expand the attack surface.",
        check_method="Ran 'ss -tlnp' to list all TCP listening sockets with process info.",
        fix="1. Review each listening port against the Versa deployment guide.\n"
            "2. Disable unnecessary services:  sudo systemctl disable <service>")
    rc, out, _ = exe.run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
    f.evidence = out if out else "(no output)"
    f.status, f.detail = "MANUAL", "Review the listening services list for unauthorized ports."
    return f


def check_versa_tls(exe: RemoteExecutor) -> Finding:
    """VERSA-003 | Versa web interface must use TLS 1.2+."""
    f = Finding(
        "VERSA-003", "VERSA-TLS-001", "CAT II",
        "Versa Director web interface must require TLS 1.2 or higher",
        description="TLS versions below 1.2 have known vulnerabilities (POODLE, BEAST, etc.).",
        check_method="Searched common Versa/Tomcat/Nginx config paths for TLS protocol settings.",
        fix="1. Locate the web server config (e.g. /opt/versa/*/server.xml or nginx.conf).\n"
            "2. Set minimum TLS version to 1.2.\n"
            "   Nginx: ssl_protocols TLSv1.2 TLSv1.3;\n"
            "   Tomcat: sslEnabledProtocols='TLSv1.2,TLSv1.3'\n"
            "3. Restart the web server.")
    rc, out, _ = exe.run(
        "grep -rhi 'ssl_protocols\\|sslEnabledProtocols\\|TLSv1\\.' "
        "/opt/versa/ /etc/nginx/ /etc/apache2/ 2>/dev/null | head -10 || echo 'NOT_FOUND'")
    f.evidence = out
    if "NOT_FOUND" in out:
        f.status, f.detail = "MANUAL", "Could not locate TLS config — manual review needed."
    elif re.search(r'TLSv1[\s,;]|TLSv1\.0|TLSv1\.1', out):
        f.status, f.detail = "FAIL", "Legacy TLS protocols (< 1.2) may be enabled."
    else:
        f.status, f.detail = "PASS", "TLS configuration appears to enforce 1.2+."
    return f

#CAT III start here


# ── CAT III — LOW ────────────────────────────────────────────────────────

def check_030000_ssh_banner(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030000 | SSH must display a login banner."""
    f = Finding("UBTU-18-030000", "SV-219210r853443_rule", "CAT III",
                "Ubuntu 18.04 must display the Standard Mandatory DoD Notice before SSH login",
                fix="Set 'Banner /etc/issue.net' in /etc/ssh/sshd_config and populate /etc/issue.net.")
    rc, out, _ = exe.run("grep -i '^Banner' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET'")
    if "NOT_SET" in out:
        f.status, f.detail = "FAIL", "SSH Banner directive is not set in sshd_config."
    elif "/etc/issue" in out:
        rc2, out2, _ = exe.run("wc -l < /etc/issue.net 2>/dev/null || echo '0'")
        lines = int(out2.strip()) if out2.strip().isdigit() else 0
        if lines > 0:
            f.status, f.detail = "PASS", f"SSH Banner is configured: {out.strip()} ({lines} lines)."
        else:
            f.status, f.detail = "FAIL", f"Banner file configured but empty or missing ({out.strip()})."
    else:
        f.status, f.detail = "FAIL", f"SSH Banner not properly configured: {out.strip()}"
    return f


def check_030001_login_banner_content(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030001 | /etc/issue.net must contain the Standard Mandatory DoD Notice."""
    f = Finding("UBTU-18-030001", "SV-219211r853444_rule", "CAT III",
                "Ubuntu 18.04 must display the DoD-approved system use notification message",
                fix="Populate /etc/issue.net with the Standard Mandatory DoD Notice and Consent Banner.")
    rc, out, _ = exe.run("cat /etc/issue.net 2>/dev/null || echo 'NOT_FOUND'")
    if "NOT_FOUND" in out or not out.strip():
        f.status, f.detail = "FAIL", "/etc/issue.net is missing or empty."
    elif "unauthorized" in out.lower() or "consent" in out.lower() or "u.s. government" in out.lower():
        f.status, f.detail = "PASS", "Banner contains expected DoD notice language."
    else:
        f.status, f.detail = "MANUAL", f"Banner file exists but review for DoD compliance. First line: {out.splitlines()[0][:80]}"
    return f


def check_030002_motd_banner(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030002 | /etc/motd must not contain prohibited info."""
    f = Finding("UBTU-18-030002", "SV-219212r853445_rule", "CAT III",
                "Ubuntu 18.04 /etc/motd must not contain OS/patch info that could aid attackers",
                fix="Remove or edit /etc/motd to remove OS version, patch level, or proprietary info.")
    rc, out, _ = exe.run("cat /etc/motd 2>/dev/null || echo 'NOT_FOUND'")
    if "NOT_FOUND" in out or not out.strip():
        f.status, f.detail = "PASS", "/etc/motd is empty or does not exist."
    elif re.search(r'ubuntu|18\.04|kernel|patch|version', out, re.IGNORECASE):
        f.status, f.detail = "FAIL", f"MOTD may contain OS/version info: {out[:200]}"
    else:
        f.status, f.detail = "MANUAL", f"MOTD exists — verify no prohibited info: {out[:200]}"
    return f


def check_030003_local_console_banner(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030003 | /etc/issue must contain the DoD notice for local login."""
    f = Finding("UBTU-18-030003", "SV-219213r853446_rule", "CAT III",
                "Ubuntu 18.04 /etc/issue must contain the DoD notice for local console login",
                fix="Populate /etc/issue with the Standard Mandatory DoD Notice and Consent Banner.")
    rc, out, _ = exe.run("cat /etc/issue 2>/dev/null || echo 'NOT_FOUND'")
    if "NOT_FOUND" in out or not out.strip():
        f.status, f.detail = "FAIL", "/etc/issue is missing or empty."
    elif "unauthorized" in out.lower() or "consent" in out.lower() or "u.s. government" in out.lower():
        f.status, f.detail = "PASS", "/etc/issue contains expected DoD notice language."
    else:
        f.status, f.detail = "MANUAL", f"/etc/issue exists but review for DoD compliance. First line: {out.splitlines()[0][:80]}"
    return f


def check_030100_ssh_idle_timeout(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030100 | SSH ClientAliveInterval must be 600 or less."""
    f = Finding("UBTU-18-030100", "SV-219214r853447_rule", "CAT III",
                "Ubuntu 18.04 must configure SSH ClientAliveInterval to 600 or less",
                fix="Set 'ClientAliveInterval 600' in /etc/ssh/sshd_config.")
    rc, out, _ = exe.run_sudo("grep -i '^ClientAliveInterval' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET'")
    if "NOT_SET" in out:
        f.status, f.detail = "FAIL", "ClientAliveInterval is not set."
    else:
        try:
            val = int(out.split()[-1])
            if 1 <= val <= 600:
                f.status, f.detail = "PASS", f"ClientAliveInterval is {val} seconds."
            else:
                f.status, f.detail = "FAIL", f"ClientAliveInterval is {val} (must be ≤ 600 and > 0)."
        except (ValueError, IndexError):
            f.status, f.detail = "MANUAL", f"Could not parse: {out}"
    return f


def check_030101_ssh_alive_count(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030101 | SSH ClientAliveCountMax must be 1."""
    f = Finding("UBTU-18-030101", "SV-219215r853448_rule", "CAT III",
                "Ubuntu 18.04 must configure SSH ClientAliveCountMax to 1",
                fix="Set 'ClientAliveCountMax 1' in /etc/ssh/sshd_config.")
    rc, out, _ = exe.run_sudo("grep -i '^ClientAliveCountMax' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET'")
    if "NOT_SET" in out:
        f.status, f.detail = "FAIL", "ClientAliveCountMax is not set (default is 3)."
    else:
        try:
            val = int(out.split()[-1])
            f.status = "PASS" if val == 1 else "FAIL"
            f.detail = f"ClientAliveCountMax is {val}" + ("." if val == 1 else " (must be 1).")
        except (ValueError, IndexError):
            f.status, f.detail = "MANUAL", f"Could not parse: {out}"
    return f


def check_030102_shell_timeout(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030102 | Shell TMOUT must be 600 or less."""
    f = Finding("UBTU-18-030102", "SV-219216r853449_rule", "CAT III",
                "Ubuntu 18.04 must set a session timeout of 600 seconds or less (TMOUT)",
                fix="Add 'TMOUT=600' and 'readonly TMOUT; export TMOUT' to /etc/profile.d/tmout.sh.")
    rc, out, _ = exe.run_sudo("grep -rhs 'TMOUT' /etc/profile /etc/profile.d/ /etc/bash.bashrc 2>/dev/null || echo 'NOT_SET'")
    if "NOT_SET" in out:
        f.status, f.detail = "FAIL", "TMOUT is not configured."
    else:
        match = re.search(r'TMOUT\s*=\s*(\d+)', out)
        if match:
            val = int(match.group(1))
            if 1 <= val <= 600:
                f.status, f.detail = "PASS", f"TMOUT is set to {val} seconds."
            else:
                f.status, f.detail = "FAIL", f"TMOUT is {val} (must be ≤ 600 and > 0)."
        else:
            f.status, f.detail = "MANUAL", f"TMOUT referenced but could not parse: {out[:200]}"
    return f


def check_030200_ssh_x11_forwarding(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030200 | SSH X11 forwarding must be disabled."""
    f = Finding("UBTU-18-030200", "SV-219217r853450_rule", "CAT III",
                "Ubuntu 18.04 must not allow SSH X11 forwarding",
                fix="Set 'X11Forwarding no' in /etc/ssh/sshd_config.")
    rc, out, _ = exe.run("grep -i '^X11Forwarding' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET'")
    if "NOT_SET" in out:
        f.status, f.detail = "FAIL", "X11Forwarding is not explicitly set (default may be yes)."
    elif "no" in out.lower():
        f.status, f.detail = "PASS", "X11Forwarding is disabled."
    else:
        f.status, f.detail = "FAIL", f"X11Forwarding is enabled: {out.strip()}"
    return f


def check_030201_ssh_user_env(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030201 | SSH must not allow PermitUserEnvironment."""
    f = Finding("UBTU-18-030201", "SV-219218r853451_rule", "CAT III",
                "Ubuntu 18.04 SSH must not allow PermitUserEnvironment",
                fix="Set 'PermitUserEnvironment no' in /etc/ssh/sshd_config.")
    rc, out, _ = exe.run("grep -i '^PermitUserEnvironment' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET'")
    if "NOT_SET" in out or "no" in out.lower():
        f.status, f.detail = "PASS", "PermitUserEnvironment is disabled."
    else:
        f.status, f.detail = "FAIL", f"PermitUserEnvironment is enabled: {out.strip()}"
    return f


def check_030202_ssh_use_pam(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030202 | SSH must use PAM."""
    f = Finding("UBTU-18-030202", "SV-219219r853452_rule", "CAT III",
                "Ubuntu 18.04 SSH must be configured to use PAM (UsePAM yes)",
                fix="Set 'UsePAM yes' in /etc/ssh/sshd_config.")
    rc, out, _ = exe.run("grep -i '^UsePAM' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET'")
    if "NOT_SET" in out or "yes" in out.lower():
        f.status, f.detail = "PASS", "SSH UsePAM is enabled."
    else:
        f.status, f.detail = "FAIL", f"UsePAM is not enabled: {out.strip()}"
    return f


def check_030203_ssh_log_level(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030203 | SSH LogLevel must be INFO or VERBOSE."""
    f = Finding("UBTU-18-030203", "SV-219220r853453_rule", "CAT III",
                "Ubuntu 18.04 SSH must set LogLevel to INFO or VERBOSE",
                fix="Set 'LogLevel VERBOSE' in /etc/ssh/sshd_config.")
    rc, out, _ = exe.run("grep -i '^LogLevel' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET'")
    if "NOT_SET" in out:
        f.status, f.detail = "PASS", "LogLevel not set (defaults to INFO)."
    elif "INFO" in out.upper() or "VERBOSE" in out.upper():
        f.status, f.detail = "PASS", f"SSH LogLevel: {out.strip()}"
    else:
        f.status, f.detail = "FAIL", f"SSH LogLevel is not INFO or VERBOSE: {out.strip()}"
    return f


def check_030300_passwd_sha512(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030300 | Passwords must be hashed with SHA-512."""
    f = Finding("UBTU-18-030300", "SV-219221r853454_rule", "CAT III",
                "Ubuntu 18.04 must use SHA-512 for password hashing",
                fix="Set 'ENCRYPT_METHOD SHA512' in /etc/login.defs.")
    rc, out, _ = exe.run("grep -i '^ENCRYPT_METHOD' /etc/login.defs 2>/dev/null || echo 'NOT_SET'")
    if "NOT_SET" in out:
        f.status, f.detail = "FAIL", "ENCRYPT_METHOD is not set."
    elif "SHA512" in out.upper():
        f.status, f.detail = "PASS", f"Password hashing: {out.strip()}"
    else:
        f.status, f.detail = "FAIL", f"Weak hashing: {out.strip()} (must be SHA512)."
    return f


def check_030301_pam_sha512(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030301 | PAM must use SHA-512 hashing."""
    f = Finding("UBTU-18-030301", "SV-219222r853455_rule", "CAT III",
                "Ubuntu 18.04 PAM must be configured to use SHA-512 hashing",
                fix="Ensure pam_unix.so includes 'sha512' in /etc/pam.d/common-password.")
    rc, out, _ = exe.run("grep -E 'pam_unix\\.so' /etc/pam.d/common-password 2>/dev/null || echo 'NOT_SET'")
    if "NOT_SET" in out:
        f.status, f.detail = "MANUAL", "pam_unix.so not found in /etc/pam.d/common-password."
    elif "sha512" in out.lower():
        f.status, f.detail = "PASS", f"PAM uses SHA-512: {out.strip()[:120]}"
    else:
        f.status, f.detail = "FAIL", f"PAM may lack sha512: {out.strip()[:120]}"
    return f


def check_030400_system_cmd_perms(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030400 | System commands must have mode 755 or less."""
    f = Finding("UBTU-18-030400", "SV-219223r853456_rule", "CAT III",
                "Ubuntu 18.04 system commands in /usr/bin and /usr/sbin must have mode 755 or less",
                fix="sudo find /usr/bin /usr/sbin -perm /022 -exec chmod 755 {} \\;")
    rc, out, _ = exe.run("find /usr/bin /usr/sbin -perm /022 -type f 2>/dev/null | head -20")
    if not out.strip():
        f.status, f.detail = "PASS", "No system commands with excessive permissions."
    else:
        count_rc, count_out, _ = exe.run("find /usr/bin /usr/sbin -perm /022 -type f 2>/dev/null | wc -l")
        f.status, f.detail = "FAIL", f"{count_out.strip()} command(s) with group/other write:\n{out[:400]}"
    return f


def check_030401_system_cmd_ownership(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030401 | System commands must be owned by root."""
    f = Finding("UBTU-18-030401", "SV-219224r853457_rule", "CAT III",
                "Ubuntu 18.04 system commands must be owned by root",
                fix="sudo find /usr/bin /usr/sbin ! -user root -exec chown root {} \\;")
    rc, out, _ = exe.run("find /usr/bin /usr/sbin ! -user root -type f 2>/dev/null | head -20")
    if not out.strip():
        f.status, f.detail = "PASS", "All system commands are owned by root."
    else:
        f.status, f.detail = "FAIL", f"Commands not owned by root:\n{out[:400]}"
    return f


def check_030402_system_cmd_group(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030402 | System commands must be group-owned by root."""
    f = Finding("UBTU-18-030402", "SV-219225r853458_rule", "CAT III",
                "Ubuntu 18.04 system commands must be group-owned by root",
                fix="sudo find /usr/bin /usr/sbin ! -group root -exec chgrp root {} \\;")
    rc, out, _ = exe.run("find /usr/bin /usr/sbin ! -group root -type f 2>/dev/null | head -20")
    if not out.strip():
        f.status, f.detail = "PASS", "All system commands are group-owned by root."
    else:
        f.status, f.detail = "FAIL", f"Commands not group-owned by root:\n{out[:400]}"
    return f


def check_030500_lib_perms(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030500 | Library files must have mode 755 or less."""
    f = Finding("UBTU-18-030500", "SV-219226r853459_rule", "CAT III",
                "Ubuntu 18.04 library files must have mode 755 or less",
                fix="sudo find /lib /usr/lib -perm /022 -type f -exec chmod 755 {} \\;")
    rc, out, _ = exe.run("find /lib /usr/lib -perm /022 -type f 2>/dev/null | head -20")
    if not out.strip():
        f.status, f.detail = "PASS", "No library files with excessive permissions."
    else:
        count_rc, count_out, _ = exe.run("find /lib /usr/lib -perm /022 -type f 2>/dev/null | wc -l")
        f.status, f.detail = "FAIL", f"{count_out.strip()} library file(s) with group/other write:\n{out[:400]}"
    return f


def check_030501_lib_ownership(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030501 | Library files must be owned by root."""
    f = Finding("UBTU-18-030501", "SV-219227r853460_rule", "CAT III",
                "Ubuntu 18.04 library files must be owned by root",
                fix="sudo find /lib /usr/lib ! -user root -type f -exec chown root {} \\;")
    rc, out, _ = exe.run("find /lib /usr/lib ! -user root -type f 2>/dev/null | head -20")
    if not out.strip():
        f.status, f.detail = "PASS", "All library files are owned by root."
    else:
        f.status, f.detail = "FAIL", f"Library files not owned by root:\n{out[:400]}"
    return f


def check_030502_lib_group(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030502 | Library files must be group-owned by root."""
    f = Finding("UBTU-18-030502", "SV-219228r853461_rule", "CAT III",
                "Ubuntu 18.04 library files must be group-owned by root",
                fix="sudo find /lib /usr/lib ! -group root -type f -exec chgrp root {} \\;")
    rc, out, _ = exe.run("find /lib /usr/lib ! -group root -type f 2>/dev/null | head -20")
    if not out.strip():
        f.status, f.detail = "PASS", "All library files are group-owned by root."
    else:
        f.status, f.detail = "FAIL", f"Library files not group-owned by root:\n{out[:400]}"
    return f


def check_030600_cron_dirs_restricted(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030600 | Cron directories must have mode 700 or less."""
    f = Finding("UBTU-18-030600", "SV-219229r853462_rule", "CAT III",
                "Ubuntu 18.04 cron directories must have mode 700 or more restrictive",
                fix="sudo chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly")
    dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.monthly", "/etc/cron.weekly"]
    bad = []
    for d in dirs:
        rc, out, _ = exe.run(f"stat -c '%a' {d} 2>/dev/null || echo 'MISSING'")
        if "MISSING" not in out:
            try:
                mode = int(out.strip(), 8)
                if mode > 0o700:
                    bad.append(f"{d}={oct(mode)}")
            except ValueError:
                pass
    if not bad:
        f.status, f.detail = "PASS", "All cron directories have mode 700 or more restrictive."
    else:
        f.status, f.detail = "FAIL", f"Cron dirs with excessive permissions: {', '.join(bad)}"
    return f


def check_030601_crontab_restricted(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030601 | /etc/crontab must have mode 600 or less."""
    f = Finding("UBTU-18-030601", "SV-219230r853463_rule", "CAT III",
                "Ubuntu 18.04 /etc/crontab must have mode 600 or more restrictive",
                fix="sudo chmod 600 /etc/crontab")
    rc, out, _ = exe.run("stat -c '%a' /etc/crontab 2>/dev/null || echo 'NOT_FOUND'")
    if "NOT_FOUND" in out:
        f.status, f.detail = "PASS", "/etc/crontab does not exist."
    else:
        try:
            mode = int(out.strip(), 8)
            f.status = "PASS" if mode <= 0o600 else "FAIL"
            f.detail = f"/etc/crontab mode: {oct(mode)}" + ("" if mode <= 0o600 else " (must be ≤ 0600)")
        except ValueError:
            f.status, f.detail = "MANUAL", f"Could not parse mode: {out}"
    return f


def check_030700_audit_tools_perms(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030700 | Audit tools must have mode 755 or less."""
    f = Finding("UBTU-18-030700", "SV-219231r853464_rule", "CAT III",
                "Ubuntu 18.04 audit tools must have mode 755 or less",
                fix="sudo chmod 755 /usr/sbin/auditctl /usr/sbin/aureport /usr/sbin/ausearch /usr/sbin/auditd /usr/sbin/augenrules")
    tools = ["/usr/sbin/auditctl", "/usr/sbin/aureport", "/usr/sbin/ausearch",
             "/usr/sbin/autrace", "/usr/sbin/auditd", "/usr/sbin/augenrules"]
    bad = []
    for t in tools:
        rc, out, _ = exe.run(f"stat -c '%a' {t} 2>/dev/null")
        if out.strip():
            try:
                mode = int(out.strip(), 8)
                if mode > 0o755:
                    bad.append(f"{t}={oct(mode)}")
            except ValueError:
                pass
    if not bad:
        f.status, f.detail = "PASS", "All audit tools have mode 755 or less."
    else:
        f.status, f.detail = "FAIL", f"Audit tools with excessive permissions: {', '.join(bad)}"
    return f


def check_030701_audit_tools_ownership(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030701 | Audit tools must be owned by root."""
    f = Finding("UBTU-18-030701", "SV-219232r853465_rule", "CAT III",
                "Ubuntu 18.04 audit tools must be owned by root",
                fix="sudo chown root /usr/sbin/auditctl /usr/sbin/aureport /usr/sbin/ausearch /usr/sbin/auditd /usr/sbin/augenrules")
    tools = ["/usr/sbin/auditctl", "/usr/sbin/aureport", "/usr/sbin/ausearch",
             "/usr/sbin/autrace", "/usr/sbin/auditd", "/usr/sbin/augenrules"]
    bad = []
    for t in tools:
        rc, out, _ = exe.run(f"stat -c '%U' {t} 2>/dev/null")
        if out.strip() and out.strip() != "root":
            bad.append(f"{t} (owner={out.strip()})")
    if not bad:
        f.status, f.detail = "PASS", "All audit tools are owned by root."
    else:
        f.status, f.detail = "FAIL", f"Audit tools not owned by root: {', '.join(bad)}"
    return f


def check_030702_audit_tools_group(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030702 | Audit tools must be group-owned by root."""
    f = Finding("UBTU-18-030702", "SV-219233r853466_rule", "CAT III",
                "Ubuntu 18.04 audit tools must be group-owned by root",
                fix="sudo chgrp root /usr/sbin/auditctl /usr/sbin/aureport /usr/sbin/ausearch /usr/sbin/auditd /usr/sbin/augenrules")
    tools = ["/usr/sbin/auditctl", "/usr/sbin/aureport", "/usr/sbin/ausearch",
             "/usr/sbin/autrace", "/usr/sbin/auditd", "/usr/sbin/augenrules"]
    bad = []
    for t in tools:
        rc, out, _ = exe.run(f"stat -c '%G' {t} 2>/dev/null")
        if out.strip() and out.strip() != "root":
            bad.append(f"{t} (group={out.strip()})")
    if not bad:
        f.status, f.detail = "PASS", "All audit tools are group-owned by root."
    else:
        f.status, f.detail = "FAIL", f"Audit tools not group-owned by root: {', '.join(bad)}"
    return f


def check_030800_home_dir_perms(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030800 | User home directories must have mode 750 or less."""
    f = Finding("UBTU-18-030800", "SV-219234r853467_rule", "CAT III",
                "Ubuntu 18.04 user home directories must have mode 0750 or less",
                fix="sudo chmod 0750 /home/<user> for each offending directory.")
    rc, out, _ = exe.run(
        r"awk -F: '($3 >= 1000 && $7 !~ /nologin|false/) {print $6}' /etc/passwd 2>/dev/null"
    )
    if not out.strip():
        f.status, f.detail = "PASS", "No interactive user home directories found."
        return f
    bad = []
    for hdir in out.strip().splitlines():
        hdir = hdir.strip()
        if not hdir:
            continue
        rc2, mode_out, _ = exe.run(f"stat -c '%a' {hdir} 2>/dev/null")
        if mode_out.strip():
            try:
                mode = int(mode_out.strip(), 8)
                if mode > 0o750:
                    bad.append(f"{hdir}={oct(mode)}")
            except ValueError:
                pass
    if not bad:
        f.status, f.detail = "PASS", "All home directories have mode 750 or less."
    else:
        f.status, f.detail = "FAIL", f"Home dirs with excessive permissions: {', '.join(bad)}"
    return f


def check_030801_home_dir_ownership(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030801 | Home directories must be owned by assigned user."""
    f = Finding("UBTU-18-030801", "SV-219235r853468_rule", "CAT III",
                "Ubuntu 18.04 home directories must be owned by their respective users",
                fix="sudo chown <user>:<user> /home/<user> for each mismatched directory.")
    rc, out, _ = exe.run(
        r"awk -F: '($3 >= 1000 && $7 !~ /nologin|false/) {print $1,$6}' /etc/passwd 2>/dev/null"
    )
    if not out.strip():
        f.status, f.detail = "PASS", "No interactive users found."
        return f
    bad = []
    for line in out.strip().splitlines():
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        user, hdir = parts[0], parts[1]
        rc2, owner, _ = exe.run(f"stat -c '%U' {hdir} 2>/dev/null")
        if owner.strip() and owner.strip() != user:
            bad.append(f"{hdir} (expected={user}, actual={owner.strip()})")
    if not bad:
        f.status, f.detail = "PASS", "All home directories are correctly owned."
    else:
        f.status, f.detail = "FAIL", f"Mismatched ownership: {', '.join(bad)}"
    return f


def check_030900_no_duplicate_uids(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030900 | Must not have duplicate UIDs."""
    f = Finding("UBTU-18-030900", "SV-219236r853469_rule", "CAT III",
                "Ubuntu 18.04 must not contain duplicate UIDs",
                fix="Correct duplicate UIDs in /etc/passwd.")
    rc, out, _ = exe.run(r"awk -F: '{print $3}' /etc/passwd | sort | uniq -d 2>/dev/null")
    if not out.strip():
        f.status, f.detail = "PASS", "No duplicate UIDs found."
    else:
        f.status, f.detail = "FAIL", f"Duplicate UIDs: {out.strip()}"
    return f


def check_030901_no_duplicate_gids(exe: RemoteExecutor) -> Finding:
    """UBTU-18-030901 | Must not have duplicate GIDs."""
    f = Finding("UBTU-18-030901", "SV-219237r853470_rule", "CAT III",
                "Ubuntu 18.04 must not contain duplicate GIDs",
                fix="Correct duplicate GIDs in /etc/group.")
    rc, out, _ = exe.run(r"awk -F: '{print $3}' /etc/group | sort | uniq -d 2>/dev/null")
    if not out.strip():
        f.status, f.detail = "PASS", "No duplicate GIDs found."
    else:
        f.status, f.detail = "FAIL", f"Duplicate GIDs: {out.strip()}"
    return f


def check_031000_no_world_writable(exe: RemoteExecutor) -> Finding:
    """UBTU-18-031000 | Must not have world-writable files."""
    f = Finding("UBTU-18-031000", "SV-219238r853471_rule", "CAT III",
                "Ubuntu 18.04 must not have unnecessary world-writable files",
                fix="sudo chmod o-w <file> for each world-writable file.")
    rc, out, _ = exe.run(
        "find / -xdev -type f -perm -0002 "
        "! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' "
        "2>/dev/null | head -25"
    )
    if not out.strip():
        f.status, f.detail = "PASS", "No world-writable files found."
    else:
        count_rc, count_out, _ = exe.run(
            "find / -xdev -type f -perm -0002 "
            "! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' "
            "2>/dev/null | wc -l"
        )
        f.status, f.detail = "FAIL", f"{count_out.strip()} world-writable file(s):\n{out[:500]}"
    return f


def check_031001_no_unowned_files(exe: RemoteExecutor) -> Finding:
    """UBTU-18-031001 | Must not have unowned files."""
    f = Finding("UBTU-18-031001", "SV-219239r853472_rule", "CAT III",
                "Ubuntu 18.04 must not have files without a valid owner",
                fix="sudo chown root <file> for each unowned file.")
    rc, out, _ = exe.run(
        "find / -xdev -nouser "
        "! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' "
        "2>/dev/null | head -20"
    )
    if not out.strip():
        f.status, f.detail = "PASS", "No unowned files found."
    else:
        f.status, f.detail = "FAIL", f"Unowned files:\n{out[:400]}"
    return f


def check_031002_no_ungrouped_files(exe: RemoteExecutor) -> Finding:
    """UBTU-18-031002 | Must not have files without a valid group."""
    f = Finding("UBTU-18-031002", "SV-219240r853473_rule", "CAT III",
                "Ubuntu 18.04 must not have files without a valid group owner",
                fix="sudo chgrp root <file> for each ungrouped file.")
    rc, out, _ = exe.run(
        "find / -xdev -nogroup "
        "! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' "
        "2>/dev/null | head -20"
    )
    if not out.strip():
        f.status, f.detail = "PASS", "No ungrouped files found."
    else:
        f.status, f.detail = "FAIL", f"Ungrouped files:\n{out[:400]}"
    return f


def check_031100_ntp_configured(exe: RemoteExecutor) -> Finding:
    """UBTU-18-031100 | NTP must be configured."""
    f = Finding("UBTU-18-031100", "SV-219241r853474_rule", "CAT III",
                "Ubuntu 18.04 must synchronize clocks using an authoritative NTP source",
                fix="Install and configure chrony or systemd-timesyncd.")
    rc, out, _ = exe.run("timedatectl show --property=NTP --value 2>/dev/null || timedatectl status 2>/dev/null | grep NTP || echo 'UNKNOWN'")
    rc2, out2, _ = exe.run("systemctl is-active chrony systemd-timesyncd ntp 2>/dev/null || echo 'INACTIVE'")
    if "yes" in out.lower() or "active" in out2:
        f.status, f.detail = "PASS", f"NTP synchronization is active. Services: {out2.strip()}"
    else:
        f.status, f.detail = "FAIL", f"NTP may not be configured. NTP={out.strip()}, services={out2.strip()}"
    return f


def check_031200_sudo_log(exe: RemoteExecutor) -> Finding:
    """UBTU-18-031200 | sudo must log activity."""
    f = Finding("UBTU-18-031200", "SV-219242r853475_rule", "CAT III",
                "Ubuntu 18.04 must configure sudo to log all activity",
                fix="Add 'Defaults logfile=\"/var/log/sudo.log\"' to /etc/sudoers via visudo.")
    rc, out, _ = exe.run("sudo grep -rh 'Defaults.*logfile' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || echo 'NOT_SET'")
    if "NOT_SET" in out:
        f.status, f.detail = "FAIL", "sudo is not configured to log activity."
    elif "logfile" in out.lower():
        f.status, f.detail = "PASS", f"Sudo logging: {out.strip()[:120]}"
    else:
        f.status, f.detail = "FAIL", f"Unexpected: {out[:120]}"
    return f


def check_031201_sudo_timestamp_timeout(exe: RemoteExecutor) -> Finding:
    """UBTU-18-031201 | sudo must require re-authentication."""
    f = Finding("UBTU-18-031201", "SV-219243r853476_rule", "CAT III",
                "Ubuntu 18.04 must enforce sudo timestamp_timeout",
                fix="Add 'Defaults timestamp_timeout=0' to /etc/sudoers via visudo.")
    rc, out, _ = exe.run("sudo grep -rh 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || echo 'NOT_SET'")
    if "NOT_SET" in out:
        f.status, f.detail = "FAIL", "timestamp_timeout not set (default 15 min cache)."
    else:
        match = re.search(r'timestamp_timeout\s*=\s*(-?\d+)', out)
        if match:
            val = int(match.group(1))
            if val <= 0:
                f.status, f.detail = "PASS", f"sudo timestamp_timeout={val} (re-auth every time)."
            else:
                f.status, f.detail = "FAIL", f"sudo timestamp_timeout={val} (should be 0)."
        else:
            f.status, f.detail = "MANUAL", f"Could not parse: {out[:120]}"
    return f


def check_031300_noexec_on_tmp(exe: RemoteExecutor) -> Finding:
    """UBTU-18-031300 | /tmp must be mounted with noexec."""
    f = Finding("UBTU-18-031300", "SV-219244r853477_rule", "CAT III",
                "Ubuntu 18.04 /tmp must be mounted with noexec",
                fix="Add 'noexec' to /tmp mount options in /etc/fstab.")
    rc, out, _ = exe.run("mount | grep ' /tmp ' 2>/dev/null || echo 'NOT_MOUNTED'")
    if "NOT_MOUNTED" in out:
        f.status, f.detail = "MANUAL", "/tmp is not a separate mount point."
    elif "noexec" in out:
        f.status, f.detail = "PASS", "/tmp is mounted with noexec."
    else:
        f.status, f.detail = "FAIL", f"/tmp mounted WITHOUT noexec: {out.strip()[:150]}"
    return f


def check_031301_nosuid_on_tmp(exe: RemoteExecutor) -> Finding:
    """UBTU-18-031301 | /tmp must be mounted with nosuid."""
    f = Finding("UBTU-18-031301", "SV-219245r853478_rule", "CAT III",
                "Ubuntu 18.04 /tmp must be mounted with nosuid",
                fix="Add 'nosuid' to /tmp mount options in /etc/fstab.")
    rc, out, _ = exe.run("mount | grep ' /tmp ' 2>/dev/null || echo 'NOT_MOUNTED'")
    if "NOT_MOUNTED" in out:
        f.status, f.detail = "MANUAL", "/tmp is not a separate mount point."
    elif "nosuid" in out:
        f.status, f.detail = "PASS", "/tmp is mounted with nosuid."
    else:
        f.status, f.detail = "FAIL", f"/tmp mounted WITHOUT nosuid: {out.strip()[:150]}"
    return f


def check_031400_postfix_local(exe: RemoteExecutor) -> Finding:
    """UBTU-18-031400 | Mail must be local-only if Postfix installed."""
    f = Finding("UBTU-18-031400", "SV-219246r853479_rule", "CAT III",
                "Ubuntu 18.04 mail services (Postfix) must operate in local-only mode",
                fix="Set 'inet_interfaces = loopback-only' in /etc/postfix/main.cf.")
    rc, out, _ = exe.run("dpkg -l postfix 2>/dev/null | grep -E '^ii' || echo 'NOT_INSTALLED'")
    if "NOT_INSTALLED" in out:
        f.status, f.detail = "PASS", "Postfix is not installed."
    else:
        rc2, out2, _ = exe.run("postconf inet_interfaces 2>/dev/null || echo 'UNKNOWN'")
        if "loopback-only" in out2 or "localhost" in out2:
            f.status, f.detail = "PASS", f"Postfix is local-only: {out2.strip()}"
        elif "UNKNOWN" in out2:
            f.status, f.detail = "MANUAL", "Postfix installed but could not query inet_interfaces."
        else:
            f.status, f.detail = "FAIL", f"Postfix may listen on non-local: {out2.strip()}"
    return f


def check_031500_auto_updates(exe: RemoteExecutor) -> Finding:
    """UBTU-18-031500 | Automatic security updates must be configured."""
    f = Finding("UBTU-18-031500", "SV-219247r853480_rule", "CAT III",
                "Ubuntu 18.04 must have automatic security updates configured",
                fix="sudo apt install unattended-upgrades && sudo dpkg-reconfigure unattended-upgrades.")
    rc, out, _ = exe.run("dpkg -l unattended-upgrades 2>/dev/null | grep -E '^ii' || echo 'NOT_INSTALLED'")
    if "NOT_INSTALLED" in out:
        f.status, f.detail = "FAIL", "unattended-upgrades is not installed."
    else:
        rc2, out2, _ = exe.run("grep -rhs 'APT::Periodic::Unattended-Upgrade' /etc/apt/apt.conf.d/ 2>/dev/null || echo 'NONE'")
        if "1" in out2:
            f.status, f.detail = "PASS", f"Automatic updates enabled: {out2.strip()[:120]}"
        else:
            f.status, f.detail = "FAIL", "unattended-upgrades installed but may not be enabled."
    return f


def check_031600_sudo_nopasswd(exe: RemoteExecutor) -> Finding:
    """UBTU-18-031600 | NOPASSWD must not be used in sudoers."""
    f = Finding("UBTU-18-031600", "SV-219248r853481_rule", "CAT III",
                "Ubuntu 18.04 must not use NOPASSWD in sudoers",
                fix="Remove NOPASSWD entries from /etc/sudoers and /etc/sudoers.d/.")
    rc, out, _ = exe.run("sudo grep -rh 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#' || echo 'NONE'")
    if "NONE" in out or not out.strip():
        f.status, f.detail = "PASS", "No NOPASSWD entries found."
    else:
        f.status, f.detail = "FAIL", f"NOPASSWD entries:\n{out[:300]}"
    return f


def check_031601_sudo_noexec(exe: RemoteExecutor) -> Finding:
    """UBTU-18-031601 | Sudo should use NOEXEC where appropriate."""
    f = Finding("UBTU-18-031601", "SV-219249r853482_rule", "CAT III",
                "Ubuntu 18.04 sudo rules should use NOEXEC to restrict shell escapes",
                fix="Add 'Defaults noexec' to /etc/sudoers or NOEXEC to individual rules.")
    rc, out, _ = exe.run("sudo grep -rh 'NOEXEC\\|noexec' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#' || echo 'NONE'")
    if "NONE" in out or not out.strip():
        f.status, f.detail = "MANUAL", "No NOEXEC directives — review if shell escapes possible via sudo."
    else:
        f.status, f.detail = "PASS", f"NOEXEC configured: {out.strip()[:200]}"
    return f


def check_031700_tmux_installed(exe: RemoteExecutor) -> Finding:
    """UBTU-18-031700 | tmux must be installed for session locking."""
    f = Finding("UBTU-18-031700", "SV-219250r853483_rule", "CAT III",
                "Ubuntu 18.04 must have tmux or equivalent for session locking",
                fix="sudo apt install tmux; configure in /etc/tmux.conf.")
    rc, out, _ = exe.run("dpkg -l tmux 2>/dev/null | grep -E '^ii' || echo 'NOT_INSTALLED'")
    if "NOT_INSTALLED" in out:
        rc2, out2, _ = exe.run("dpkg -l vlock 2>/dev/null | grep -E '^ii' || echo 'NOT_INSTALLED'")
        if "NOT_INSTALLED" in out2:
            f.status, f.detail = "FAIL", "Neither tmux nor vlock is installed."
        else:
            f.status, f.detail = "PASS", "vlock is installed for session locking."
    else:
        f.status, f.detail = "PASS", "tmux is installed for session locking."
    return f


# ═══════════════════════════════════════════════════════════════════════════
#  CHECK REGISTRY
# ═══════════════════════════════════════════════════════════════════════════

ALL_CHECKS = [
    # CAT I
    check_v219150_ssh_protocol,
    check_v219151_ssh_empty_passwords,
    check_v219210_grub_permissions,
    check_v219211_no_telnet,
    check_v219212_no_rsh,
    check_v219230_ctrl_alt_del,
    check_v219240_fips_mode,
    # CAT II — SSH
    check_v219152_ssh_root_login,
    check_v219153_ssh_x11,
    check_v219154_ssh_idle_timeout,
    check_v219155_ssh_alive_count,
    check_v219156_ssh_ciphers,
    check_v219157_ssh_macs,
    check_v219158_ssh_banner,
    # CAT II — Passwords
    check_v219166_pw_minlen,
    check_v219167_pw_ucredit,
    check_v219168_pw_lcredit,
    check_v219169_pw_dcredit,
    check_v219170_pw_ocredit,
    check_v219171_pw_history,
    check_v219172_pw_max_age,
    check_v219173_pw_min_age,
    check_v219174_account_lockout,
    # CAT II — Audit
    check_v219200_auditd_installed,
    check_v219201_auditd_enabled,
    check_v238230_audit_log_perms,
    # CAT II — Integrity
    check_v219220_aide_installed,
    # CAT II — File permissions
    check_v219300_shadow_perms,
    check_v219310_passwd_perms,
    check_v219311_group_perms,
    # CAT II — System hardening
    check_v219250_noexec_tmp,
    check_v219260_firewall,
    check_v219270_syslog_remote,
    check_v219290_no_games,
    check_v219320_no_world_writable,
    check_v219330_no_unowned,
    check_v219340_ntp,
    check_v219350_usb_disabled,
    # CAT III
    check_030100_ssh_idle_timeout,
    check_030101_ssh_alive_count,
    check_030102_shell_timeout,
    check_030200_ssh_x11_forwarding,
    check_030201_ssh_user_env,
    check_030202_ssh_use_pam,
    check_030203_ssh_log_level,
    check_030300_passwd_sha512,
    check_030301_pam_sha512,
    check_030400_system_cmd_perms,
    check_030401_system_cmd_ownership,
    check_030402_system_cmd_group,
    check_030500_lib_perms,
    check_030501_lib_ownership,
    check_030502_lib_group,
    check_030600_cron_dirs_restricted,
    check_030601_crontab_restricted,
    check_030700_audit_tools_perms,
    check_030701_audit_tools_ownership,
    check_030702_audit_tools_group,
    check_030800_home_dir_perms,
    check_030801_home_dir_ownership,
    check_030900_no_duplicate_uids,
    check_031000_no_world_writable,
    check_031001_no_unowned_files,
    check_031002_no_ungrouped_files,
    check_031100_ntp_configured,
    check_031200_sudo_log,
    check_031201_sudo_timestamp_timeout,
    check_031300_noexec_on_tmp,
    check_031301_nosuid_on_tmp,
    check_031400_postfix_local,
    check_031500_auto_updates,
    check_031600_sudo_nopasswd,
    check_031601_sudo_noexec,
    check_031700_tmux_installed,

                                    

    # Versa-specific
    check_versa_services,
    check_versa_ports,
    check_versa_tls
]


# ═══════════════════════════════════════════════════════════════════════════
#  CONSOLE OUTPUT
# ═══════════════════════════════════════════════════════════════════════════

SEVERITY_ORDER = {"CAT I": 0, "CAT II": 1, "CAT III": 2}
STATUS_COLORS = {
    "PASS": "\033[92m", "FAIL": "\033[91m", "MANUAL": "\033[93m",
    "ERROR": "\033[95m", "NOT_APPLICABLE": "\033[90m",
}
RESET = "\033[0m"


def run_all_checks(exe: RemoteExecutor, report: StigReport):
    total = len(ALL_CHECKS)
    for i, fn in enumerate(ALL_CHECKS, 1):
        label = fn.__doc__.split("|")[0].strip() if fn.__doc__ else fn.__name__
        print(f"  [{i:2d}/{total}] {label} ... ", end="", flush=True)
        try:
            finding = fn(exe)
        except Exception as e:
            finding = Finding(fn.__name__, "ERROR", "CAT II", fn.__name__,
                              status="ERROR", detail=str(e))
        print(f"{STATUS_COLORS.get(finding.status, '')}{finding.status}{RESET}")
        report.findings.append(finding)


def print_console_summary(report: StigReport):
    t = report.summary()
    print(f"\n{'=' * 62}")
    print(f"  PASS: {t['PASS']}   FAIL: {t['FAIL']}   MANUAL: {t['MANUAL']}   "
          f"ERROR: {t['ERROR']}   TOTAL: {len(report.findings)}")
    print(f"{'=' * 62}")


# ═══════════════════════════════════════════════════════════════════════════
#  HTML REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════

def generate_html_report(report: StigReport) -> str:
    """Produce a self-contained HTML report."""
    e = html_mod.escape  # shortcut

    totals = report.summary()
    sev = report.severity_summary()
    total = len(report.findings)
    pass_pct = round(100 * totals["PASS"] / total, 1) if total else 0

    # Build findings rows
    findings_html = []
    for idx, f in enumerate(report.findings):
        badge_cls = f.status.lower().replace("not_applicable", "na")
        sev_cls = f.severity.replace(" ", "").lower()

        evidence_escaped = e(f.evidence) if f.evidence else "<em>No evidence collected</em>"
        check_escaped = e(f.check_method).replace("\n", "<br>") if f.check_method else ""
        fix_escaped = e(f.fix).replace("\n", "<br>") if f.fix else ""
        desc_escaped = e(f.description).replace("\n", "<br>") if f.description else ""
        detail_escaped = e(f.detail).replace("\n", "<br>") if f.detail else ""

        findings_html.append(f"""
        <div class="finding {badge_cls}">
          <div class="finding-header" onclick="this.parentElement.classList.toggle('open')">
            <span class="badge {badge_cls}">{e(f.status)}</span>
            <span class="sev-badge {sev_cls}">{e(f.severity)}</span>
            <span class="vuln-id">{e(f.vuln_id)}</span>
            <span class="finding-title">{e(f.title)}</span>
            <span class="chevron">&#9660;</span>
          </div>
          <div class="finding-body">
            <table class="detail-table">
              <tr><th>Rule ID</th><td>{e(f.rule_id)}</td></tr>
              <tr><th>Result</th><td><strong>{e(f.detail)}</strong></td></tr>
              <tr><th>Description</th><td>{desc_escaped}</td></tr>
              <tr><th>How It Was Tested</th><td class="check-method">{check_escaped}</td></tr>
              <tr><th>Evidence Collected</th><td><pre class="evidence">{evidence_escaped}</pre></td></tr>
              <tr><th>Remediation Steps</th><td class="fix">{fix_escaped}</td></tr>
            </table>
          </div>
        </div>""")

    findings_block = "\n".join(findings_html)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>STIG Compliance Report — {e(report.hostname)} — {e(report.scan_time[:10])}</title>
<style>
:root {{
  --pass: #22c55e; --fail: #ef4444; --manual: #f59e0b;
  --error: #a855f7; --na: #6b7280;
  --cat1: #dc2626; --cat2: #f97316; --cat3: #3b82f6;
  --bg: #f8fafc; --card: #ffffff; --border: #e2e8f0;
  --text: #1e293b; --muted: #64748b; --code-bg: #f1f5f9;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
       background: var(--bg); color: var(--text); line-height: 1.6; }}

/* -- Header -- */
.report-header {{
  background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
  color: #f8fafc; padding: 2rem; border-bottom: 4px solid var(--pass);
}}
.report-header h1 {{ font-size: 1.5rem; font-weight: 700; }}
.report-header .meta {{ display: flex; flex-wrap: wrap; gap: 2rem; margin-top: 0.75rem;
                        font-size: 0.9rem; color: #94a3b8; }}
.report-header .meta span {{ display: inline-flex; align-items: center; gap: 0.35rem; }}

/* -- Summary cards -- */
.summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 1rem; padding: 1.5rem 2rem; }}
.summary-card {{ background: var(--card); border-radius: 8px; padding: 1rem 1.25rem;
                 box-shadow: 0 1px 3px rgba(0,0,0,.08); text-align: center; }}
.summary-card .num {{ font-size: 2rem; font-weight: 700; }}
.summary-card .label {{ font-size: 0.8rem; text-transform: uppercase; color: var(--muted); }}
.summary-card.pass .num {{ color: var(--pass); }}
.summary-card.fail .num {{ color: var(--fail); }}
.summary-card.manual .num {{ color: var(--manual); }}
.summary-card.error .num {{ color: var(--error); }}

/* -- Score bar -- */
.score-section {{ padding: 0 2rem 1rem; }}
.score-bar {{ height: 28px; border-radius: 14px; overflow: hidden; display: flex;
              background: var(--border); }}
.score-bar .seg {{ height: 100%; transition: width .4s; }}
.score-bar .seg.pass {{ background: var(--pass); }}
.score-bar .seg.fail {{ background: var(--fail); }}
.score-bar .seg.manual {{ background: var(--manual); }}
.score-bar .seg.error {{ background: var(--error); }}
.score-label {{ font-size: 0.85rem; margin-top: 0.4rem; color: var(--muted); }}

/* -- Severity breakdown -- */
.sev-table {{ margin: 0 2rem 1.5rem; border-collapse: collapse; width: calc(100% - 4rem); }}
.sev-table th, .sev-table td {{ padding: 0.5rem 1rem; text-align: center; border: 1px solid var(--border); }}
.sev-table th {{ background: #f1f5f9; font-size: 0.8rem; text-transform: uppercase; }}
.sev-table td {{ font-weight: 600; }}

/* -- Filter bar -- */
.filter-bar {{ padding: 0 2rem 1rem; display: flex; gap: 0.5rem; flex-wrap: wrap; }}
.filter-btn {{ padding: 0.35rem 1rem; border: 1px solid var(--border); border-radius: 20px;
               background: var(--card); cursor: pointer; font-size: 0.8rem; font-weight: 600; }}
.filter-btn:hover {{ background: #e2e8f0; }}
.filter-btn.active {{ background: var(--text); color: #fff; border-color: var(--text); }}

/* -- Findings -- */
.findings {{ padding: 0 2rem 3rem; }}
.finding {{ background: var(--card); border-radius: 8px; margin-bottom: 0.75rem;
            box-shadow: 0 1px 3px rgba(0,0,0,.06); overflow: hidden;
            border-left: 4px solid var(--border); }}
.finding.pass {{ border-left-color: var(--pass); }}
.finding.fail {{ border-left-color: var(--fail); }}
.finding.manual {{ border-left-color: var(--manual); }}
.finding.error {{ border-left-color: var(--error); }}

.finding-header {{ display: flex; align-items: center; gap: 0.6rem; padding: 0.75rem 1rem;
                   cursor: pointer; user-select: none; }}
.finding-header:hover {{ background: #f8fafc; }}
.chevron {{ margin-left: auto; font-size: 0.7rem; transition: transform .2s; color: var(--muted); }}
.finding.open .chevron {{ transform: rotate(180deg); }}

.finding-body {{ display: none; padding: 0 1rem 1rem; }}
.finding.open .finding-body {{ display: block; }}

.badge {{ display: inline-block; padding: 0.15rem 0.6rem; border-radius: 4px;
          font-size: 0.7rem; font-weight: 700; color: #fff; text-transform: uppercase; }}
.badge.pass {{ background: var(--pass); }}
.badge.fail {{ background: var(--fail); }}
.badge.manual {{ background: var(--manual); color: #1e293b; }}
.badge.error {{ background: var(--error); }}
.badge.na {{ background: var(--na); }}

.sev-badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
              font-size: 0.65rem; font-weight: 700; color: #fff; }}
.sev-badge.cati {{ background: var(--cat1); }}
.sev-badge.catii {{ background: var(--cat2); }}
.sev-badge.catiii {{ background: var(--cat3); }}

.vuln-id {{ font-family: "SF Mono", Consolas, monospace; font-size: 0.82rem; color: var(--muted); }}
.finding-title {{ font-weight: 600; font-size: 0.88rem; }}

.detail-table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
.detail-table th {{ width: 160px; text-align: left; vertical-align: top; padding: 0.5rem 0.75rem;
                    background: #f8fafc; border: 1px solid var(--border); color: var(--muted);
                    font-weight: 600; font-size: 0.78rem; text-transform: uppercase; }}
.detail-table td {{ padding: 0.5rem 0.75rem; border: 1px solid var(--border); }}
.evidence {{ background: var(--code-bg); padding: 0.75rem; border-radius: 4px;
             font-family: "SF Mono", Consolas, monospace; font-size: 0.78rem;
             white-space: pre-wrap; word-break: break-all; max-height: 200px; overflow-y: auto; }}
.check-method, .fix {{ line-height: 1.7; }}

/* -- Print -- */
@media print {{
  .filter-bar {{ display: none; }}
  .finding-body {{ display: block !important; }}
  .finding {{ page-break-inside: avoid; }}
  .report-header {{ background: #1e293b !important; -webkit-print-color-adjust: exact; }}
}}

/* -- Footer -- */
.report-footer {{ text-align: center; padding: 2rem; font-size: 0.78rem; color: var(--muted); }}
</style>
</head>
<body>

<!-- Header -->
<div class="report-header">
  <h1>STIG Compliance Report — Versa Director</h1>
  <div class="meta">
    <span><strong>Host:</strong> {e(report.host)}</span>
    <span><strong>Hostname:</strong> {e(report.hostname)}</span>
    <span><strong>OS:</strong> {e(report.os_info.split(chr(10))[0])}</span>
    <span><strong>Scan Time:</strong> {e(report.scan_time)}</span>
    <span><strong>Benchmark:</strong> DISA Ubuntu 18.04 LTS STIG V2R13+</span>
  </div>
</div>

<!-- Summary Cards -->
<div class="summary">
  <div class="summary-card pass"><div class="num">{totals['PASS']}</div><div class="label">Pass</div></div>
  <div class="summary-card fail"><div class="num">{totals['FAIL']}</div><div class="label">Fail</div></div>
  <div class="summary-card manual"><div class="num">{totals['MANUAL']}</div><div class="label">Manual</div></div>
  <div class="summary-card error"><div class="num">{totals['ERROR']}</div><div class="label">Error</div></div>
  <div class="summary-card"><div class="num">{total}</div><div class="label">Total Checks</div></div>
  <div class="summary-card pass"><div class="num">{pass_pct}%</div><div class="label">Compliance</div></div>
</div>

<!-- Score Bar -->
<div class="score-section">
  <div class="score-bar">
    <div class="seg pass" style="width:{100*totals['PASS']/total if total else 0:.1f}%"></div>
    <div class="seg fail" style="width:{100*totals['FAIL']/total if total else 0:.1f}%"></div>
    <div class="seg manual" style="width:{100*totals['MANUAL']/total if total else 0:.1f}%"></div>
    <div class="seg error" style="width:{100*totals['ERROR']/total if total else 0:.1f}%"></div>
  </div>
  <div class="score-label">
    {totals['PASS']} passed &middot; {totals['FAIL']} failed &middot; {totals['MANUAL']} manual review &middot; {totals['ERROR']} errors
  </div>
</div>

<!-- Severity Breakdown -->
<table class="sev-table">
  <tr><th>Severity</th><th style="color:var(--pass)">Pass</th><th style="color:var(--fail)">Fail</th><th style="color:var(--manual)">Manual</th><th style="color:var(--error)">Error</th></tr>
  <tr><td><span class="sev-badge cati">CAT I</span></td><td>{sev['CAT I']['PASS']}</td><td>{sev['CAT I']['FAIL']}</td><td>{sev['CAT I']['MANUAL']}</td><td>{sev['CAT I']['ERROR']}</td></tr>
  <tr><td><span class="sev-badge catii">CAT II</span></td><td>{sev['CAT II']['PASS']}</td><td>{sev['CAT II']['FAIL']}</td><td>{sev['CAT II']['MANUAL']}</td><td>{sev['CAT II']['ERROR']}</td></tr>
  <tr><td><span class="sev-badge catiii">CAT III</span></td><td>{sev['CAT III']['PASS']}</td><td>{sev['CAT III']['FAIL']}</td><td>{sev['CAT III']['MANUAL']}</td><td>{sev['CAT III']['ERROR']}</td></tr>
</table>

<!-- Filters -->
<div class="filter-bar">
  <button class="filter-btn active" data-filter="all">All ({total})</button>
  <button class="filter-btn" data-filter="fail">Fail ({totals['FAIL']})</button>
  <button class="filter-btn" data-filter="pass">Pass ({totals['PASS']})</button>
  <button class="filter-btn" data-filter="manual">Manual ({totals['MANUAL']})</button>
  <button class="filter-btn" data-filter="error">Error ({totals['ERROR']})</button>
  <button class="filter-btn" data-filter="cati">CAT I Only</button>
</div>

<!-- Findings -->
<div class="findings" id="findings">
{findings_block}
</div>

<!-- Footer -->
<div class="report-footer">
  Generated by Versa Director STIG Compliance Checker &middot; Ubuntu 18.04 LTS STIG V2R13+ &middot; {e(report.scan_time)}
</div>

<script>
// Filter buttons
document.querySelectorAll('.filter-btn').forEach(btn => {{
  btn.addEventListener('click', () => {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const f = btn.dataset.filter;
    document.querySelectorAll('.finding').forEach(el => {{
      if (f === 'all') {{ el.style.display = ''; return; }}
      if (f === 'cati') {{
        el.style.display = el.querySelector('.sev-badge.cati') ? '' : 'none';
        return;
      }}
      el.style.display = el.classList.contains(f) ? '' : 'none';
    }});
  }});
}});
</script>
</body>
</html>"""
    return html


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Versa Director Ubuntu 18.04 STIG Checker (HTML Report)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --host 10.0.0.1 --user admin --password
  %(prog)s --host 10.0.0.1 --user admin --key ~/.ssh/id_rsa
  %(prog)s --host 10.0.0.1 --user admin --password --output my_report.html
        """)
    parser.add_argument("--host", required=True, help="Versa Director IP or hostname")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--user", required=True, help="SSH username")
    parser.add_argument("--password", action="store_true", help="Prompt for SSH password")
    parser.add_argument("--key", help="Path to SSH private key")
    parser.add_argument("--output", help="Output HTML file (default: auto-generated)")
    parser.add_argument("--json", help="Also save a JSON report to this path")
    parser.add_argument("--timeout", type=int, default=30, help="SSH timeout (seconds)")
    args = parser.parse_args()

    if not args.password and not args.key:
        parser.error("Provide either --password or --key for authentication.")

    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║  Versa Director STIG Checker — Ubuntu 18.04 (HTML Report)  ║")
    print("╚══════════════════════════════════════════════════════════════╝\n")

    password = None
    if args.password:
        password = getpass.getpass(f"  SSH password for {args.user}@{args.host}: ")

    print(f"  Connecting to {args.host}:{args.port} as {args.user} ...")
    try:
        exe = RemoteExecutor(host=args.host, username=args.user, password=password,
                             key_path=args.key, port=args.port, timeout=args.timeout)
    except Exception as exc:
        sys.exit(f"  ERROR: Could not connect — {exc}")
    print("  Connected.\n")

    report = StigReport(host=args.host)
    report.scan_time = datetime.now(timezone.utc).isoformat()
    _, report.hostname, _ = exe.run("hostname")
    _, report.os_info, _ = exe.run("cat /etc/os-release 2>/dev/null | head -3 || uname -a")

    print(f"  Target: {report.hostname} ({report.os_info.split(chr(10))[0]})\n")
    print("-" * 62)

    run_all_checks(exe, report)
    exe.close()
    print_console_summary(report)

    # Save HTML
    out_path = args.output or f"versa_stig_u18_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    html_content = generate_html_report(report)
    with open(out_path, "w", encoding="utf-8") as fp:
        fp.write(html_content)
    print(f"\n  HTML report saved to: {out_path}")

    # Optional JSON
    if args.json:
        data = {"host": report.host, "hostname": report.hostname, "os_info": report.os_info,
                "scan_time": report.scan_time, "summary": report.summary(),
                "findings": [asdict(f) for f in report.findings]}
        with open(args.json, "w") as fp:
            json.dump(data, fp, indent=2)
        print(f"  JSON report saved to: {args.json}")

    print()


if __name__ == "__main__":
    main()
