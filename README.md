# Ubuntu Bare Metal Server Hardening

One-shot script to harden a fresh Ubuntu server with a public IP. After running, the only way in is via Tailscale SSH. All public traffic is restricted to Cloudflare-proxied HTTPS and two public API ports (8080/8081).

## Usage

```bash
sudo bash ubuntu-initial-setup.sh
```

You'll be prompted for an optional Tailscale auth key (recommended for physical/headless setup). Generate one at [login.tailscale.com/admin/settings/keys](https://login.tailscale.com/admin/settings/keys).

## What It Does

### Network

| What | Detail |
|---|---|
| SSH (22) | Tailscale interface only (`tailscale0`) |
| HTTPS (443) | Cloudflare IPs only (v4 + v6) |
| HTTP (80) | Closed by default, helper to enable with Cloudflare-only |
| 8080, 8081 | Public (domain-fronted HTTP API services) |
| DNS | Over TLS via Cloudflare (`1.1.1.1`) |
| All other ports | Blocked (UFW default deny incoming) |

### Authentication & Access

| What | Detail |
|---|---|
| SSH auth | Key-only, no passwords, no empty passwords |
| SSH crypto | chacha20-poly1305, aes256-gcm; curve25519 kex |
| SSH limits | 3 max attempts, 20s login grace, no forwarding |
| Fail2Ban | 24h ban after 3 failed SSH attempts |
| Login banner | Legal warning on connect |
| Root login | Key-only (`prohibit-password`) |

### System Hardening

| What | Detail |
|---|---|
| Kernel (sysctl) | ASLR, SYN cookies, no pings, no redirects, no source routing, log martians, restrict ptrace/dmesg/kptr |
| AppArmor | Enabled and enforced |
| Core dumps | Disabled |
| Shared memory | Mounted noexec/nosuid/nodev |
| SUID/SGID | Stripped from `chfn`, `chsh`, `newgrp`, `pppd`; full audit logged |
| Kernel modules | Disabled: cramfs, hfs, squashfs, udf, dccp, sctp, rds, tipc, usb-storage |
| Umask | 027 (new files not world-readable) |
| Cron/At | Root only |

### Monitoring & Detection

| What | Detail |
|---|---|
| Auditd | Watches `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, SSH keys, sshd_config, UFW rules, network config. Immutable rules. |
| AIDE | File integrity monitoring, daily cron check, logs to `/var/log/aide/` |
| rkhunter + chkrootkit | Installed with baseline captured |
| Lynis | Baseline security audit saved to `/var/log/lynis/` |

### Auto-Maintenance

| What | Detail |
|---|---|
| Security updates | `unattended-upgrades` enabled, no auto-reboot |
| `needrestart` | Flags services needing restart after updates |

### Tools Installed

| Tool | Purpose |
|---|---|
| Tailscale | VPN mesh for SSH access |
| Docker | Container runtime (CE + Buildx + Compose) |
| uv | Python package/project manager |
| tmux, htop, btop | Session management, monitoring |

### Service User

A locked non-root user `svc` is created for running applications (FastAPI, etc.). Added to the `docker` group. Switch to it with `su - svc`. Never run services as root.

## Helper Scripts

| Script | Purpose |
|---|---|
| `/usr/local/sbin/enable-http-cloudflare.sh` | Opens port 80, Cloudflare IPs only |
| `/usr/local/sbin/update-cloudflare-ips.sh` | Refreshes Cloudflare IP ranges in UFW |

## Maintenance Commands

```bash
rkhunter --check              # Scan for rootkits
aide --check                  # Check file integrity
lynis audit system            # Re-run security audit
ausearch -k ssh_keys          # Review SSH key changes
ausearch -k sshd_config       # Review sshd config changes
cat /var/log/hardening/suid-sgid-after.txt  # View SUID/SGID binaries
```
