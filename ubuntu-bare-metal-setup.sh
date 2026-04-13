#!/usr/bin/env bash
set -e

# ============================================
#  Secure Ubuntu Bare Metal Server Hardening
# ============================================

# --- Colors and helpers ---
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
print_status()  { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error()   { echo -e "${RED}[ERR]${NC} $1"; }

# --- Preflight checks ---
if [[ $(id -u) -ne 0 ]]; then
  print_error "Please run as root (use: sudo $0)"
  exit 1
fi
if grep -qi Microsoft /proc/version 2>/dev/null; then
  print_error "Running inside WSL is not supported"
  exit 1
fi

echo -e "${GREEN}Starting secure Ubuntu server hardening...${NC}"
echo ""

# --- Optional: pre-generated Tailscale auth key (headless / physical console) ---
# Generate one at: https://login.tailscale.com/admin/settings/keys
read -e -p "Tailscale auth key (paste it, or press Enter to use browser login): " TS_AUTHKEY

# ============================================
#  1. System Updates & Essential Packages
# ============================================
print_status "Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qy
apt-get upgrade -qy
apt-get install -qy \
  vim nano tmux curl git htop btop \
  ufw fail2ban unattended-upgrades \
  apparmor apparmor-utils \
  auditd \
  rkhunter chkrootkit \
  libpam-tmpdir apt-listchanges needrestart \
  aide aide-common lynis

apt-get install -qy audispd-plugins 2>/dev/null || true

# ============================================
#  2. Install Tailscale
# ============================================
print_status "Installing Tailscale..."
curl -fsSL https://tailscale.com/install.sh | sh
systemctl enable tailscaled
systemctl start tailscaled

if [[ -n "$TS_AUTHKEY" ]]; then
  print_status "Authenticating Tailscale with auth key..."
  tailscale up --authkey="$TS_AUTHKEY"
else
  echo ""
  print_warning "═══════════════════════════════════════════════════════"
  print_warning "  Tailscale authentication required.                   "
  print_warning "  A login URL will appear — open it in your browser.   "
  print_warning "  After this script completes, SSH will ONLY work      "
  print_warning "  via Tailscale. Make sure you can reach this machine. "
  print_warning "═══════════════════════════════════════════════════════"
  echo ""
  tailscale up
fi

TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || true)
if [[ -z "$TAILSCALE_IP" ]]; then
  print_error "Tailscale did not connect. Cannot lock SSH to Tailscale."
  print_error "Aborting for safety. Connect Tailscale manually, then re-run."
  exit 1
fi
print_status "Tailscale connected: $TAILSCALE_IP"

# ============================================
#  3. Install uv (Astral Python manager)
# ============================================
print_status "Installing uv..."
curl -LsSf https://astral.sh/uv/install.sh | bash
if ! grep -q 'local/bin' /root/.bashrc 2>/dev/null; then
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> /root/.bashrc
fi
export PATH="$HOME/.local/bin:$PATH"

# ============================================
#  4. Install Docker
# ============================================
print_status "Installing Docker..."
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update -qy
apt-get install -qy docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

systemctl enable docker
systemctl start docker

# ============================================
#  5. Secure /root/.ssh
# ============================================
print_status "Securing SSH directory..."
mkdir -p /root/.ssh
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys 2>/dev/null || true
cat << 'EOF' > /root/.ssh/config
Host *
  ServerAliveInterval 60
EOF
chmod 600 /root/.ssh/config

# ============================================
#  6. Harden SSH Daemon
# ============================================
print_status "Hardening SSH..."
SSH_CONFIG="/etc/ssh/sshd_config"
cp "$SSH_CONFIG" "${SSH_CONFIG}.bak.$(date +%s)"

perl -ni -e 'print unless /^\s*(PermitEmptyPasswords|PermitRootLogin|PasswordAuthentication|ChallengeResponseAuthentication|Port|X11Forwarding|MaxAuthTries|LoginGraceTime|AllowTcpForwarding|AllowAgentForwarding|ClientAliveInterval|ClientAliveCountMax|MaxSessions|Ciphers|MACs|KexAlgorithms|Banner)\s/' "$SSH_CONFIG"

cat << 'EOF' >> "$SSH_CONFIG"

# --- Hardened SSH (applied by ubuntu-initial-setup.sh) ---
Port 22
PasswordAuthentication no
ChallengeResponseAuthentication no
PermitEmptyPasswords no
PermitRootLogin prohibit-password
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 20
AllowTcpForwarding no
AllowAgentForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
MaxSessions 3
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
Banner /etc/issue.net
EOF

systemctl reload ssh || systemctl restart ssh

# ============================================
#  7. Firewall (UFW) — Maximum Lockdown
# ============================================
print_status "Configuring firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# SSH: Tailscale interface only
ufw allow in on tailscale0 to any port 22 proto tcp comment 'SSH via Tailscale only'

# HTTP API (public — fronted by domain names)
ufw allow 8080/tcp comment 'HTTP API public'
ufw allow 8081/tcp comment 'HTTP API public'

# HTTPS (443): Cloudflare IPv4 ranges only
for cidr in \
  173.245.48.0/20 \
  103.21.244.0/22 \
  103.22.200.0/22 \
  103.31.4.0/22 \
  141.101.64.0/18 \
  108.162.192.0/18 \
  190.93.240.0/20 \
  188.114.96.0/20 \
  197.234.240.0/22 \
  198.41.128.0/17 \
  162.158.0.0/15 \
  104.16.0.0/13 \
  104.24.0.0/14 \
  172.64.0.0/13 \
  131.0.72.0/22; do
  ufw allow from "$cidr" to any port 443 proto tcp comment 'HTTPS Cloudflare'
done

# HTTPS (443): Cloudflare IPv6 ranges
for cidr in \
  2400:cb00::/32 \
  2606:4700::/32 \
  2803:f800::/32 \
  2405:b500::/32 \
  2405:8100::/32 \
  2a06:98c0::/29 \
  2c0f:f248::/32; do
  ufw allow from "$cidr" to any port 443 proto tcp comment 'HTTPS Cloudflare v6'
done

ufw --force enable

# ============================================
#  8. Fail2Ban
# ============================================
print_status "Configuring Fail2Ban..."
systemctl enable fail2ban

cat << 'EOF' > /etc/fail2ban/jail.local
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 3

[sshd]
enabled  = true
port     = 22
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 5
bantime  = 24h
findtime = 10m
EOF

systemctl restart fail2ban

# ============================================
#  9. Automatic Security Updates
# ============================================
print_status "Configuring automatic security updates..."
cat << 'EOF' > /etc/apt/apt.conf.d/51unattended-upgrades-local
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
EOF
systemctl enable unattended-upgrades

# ============================================
# 10. Kernel Hardening (sysctl)
# ============================================
print_status "Applying kernel hardening..."
cat << 'EOF' > /etc/sysctl.d/99-hardening.conf
# --- Network ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# --- Kernel ---
net.core.bpf_jit_harden = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 2
kernel.sysrq = 0
kernel.randomize_va_space = 2
dev.tty.ldisc_autoload = 0
kernel.perf_event_paranoid = 3
fs.suid_dumpable = 0
kernel.core_pattern=|/bin/false

# --- File system ---
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF

sysctl --system

# ============================================
# 11. Secure Shared Memory
# ============================================
print_status "Securing shared memory..."
if ! grep -q '/run/shm' /etc/fstab; then
  echo 'tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0' >> /etc/fstab
fi

# ============================================
# 12. Disable Core Dumps
# ============================================
print_status "Disabling core dumps..."
cat << 'EOF' > /etc/security/limits.d/no-core-dumps.conf
* hard core 0
* soft core 0
EOF

# ============================================
# 13. AppArmor
# ============================================
print_status "Enforcing AppArmor profiles..."
systemctl enable apparmor
aa-enforce /etc/apparmor.d/* 2>/dev/null || true

# ============================================
# 14. Auditd (system call auditing)
# ============================================
print_status "Configuring audit logging..."
systemctl enable auditd

cat << 'EOF' > /etc/audit/rules.d/hardening.rules
-w /etc/pam.d/ -p wa -k pam_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/passwd -p wa -k passwd_changes
-w /etc/group -p wa -k group_changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes
-w /root/.ssh/ -p wa -k ssh_keys
-w /etc/hosts -p wa -k hosts_changes
-w /etc/network/ -p wa -k network_changes
-w /etc/sysctl.conf -p wa -k sysctl_changes
-w /etc/ufw/ -p wa -k ufw_changes
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Make audit config immutable until reboot
-e 2
EOF

systemctl restart auditd

# ============================================
# 15. Disable Unused Kernel Modules
# ============================================
print_status "Disabling unused kernel modules..."
cat << 'EOF' > /etc/modprobe.d/hardening.conf
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install usb-storage /bin/true
EOF

# ============================================
# 16. Rootkit Detection
# ============================================
print_status "Initializing rootkit detection baseline..."
rkhunter --update 2>/dev/null || true
rkhunter --propupd 2>/dev/null || true

# ============================================
# 17. Login Banner
# ============================================
cat << 'EOF' > /etc/issue.net
*******************************************************************
  UNAUTHORIZED ACCESS TO THIS SYSTEM IS PROHIBITED.
  All connections are monitored and recorded. Disconnect
  immediately if you are not an authorized user.
*******************************************************************
EOF

# ============================================
# 18. Restrictive Default Umask
# ============================================
sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs 2>/dev/null || true

# ============================================
# 19. Non-Root Service User
# ============================================
SVC_USER="svc"
print_status "Creating non-root service user '$SVC_USER'..."
if ! id "$SVC_USER" &>/dev/null; then
  useradd -m -s /bin/bash "$SVC_USER"
  passwd -l "$SVC_USER"
  mkdir -p /home/$SVC_USER/.ssh
  chmod 700 /home/$SVC_USER/.ssh
  chown -R $SVC_USER:$SVC_USER /home/$SVC_USER/.ssh
fi
usermod -aG docker "$SVC_USER"

# ============================================
# 20. AIDE (File Integrity Monitoring)
# ============================================
print_status "Initializing AIDE file integrity database..."
if [[ -f /usr/sbin/aideinit ]]; then
  aideinit -y -f 2>/dev/null || true
  cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
fi

cat << 'EOF' > /etc/cron.daily/aide-check
#!/usr/bin/env bash
LOGFILE="/var/log/aide/aide-$(date +%Y%m%d).log"
mkdir -p /var/log/aide
/usr/bin/aide --check > "$LOGFILE" 2>&1
if [[ $? -ne 0 ]]; then
  echo "AIDE detected filesystem changes — see $LOGFILE" | logger -t aide-check -p auth.warning
fi
EOF
chmod 700 /etc/cron.daily/aide-check

# ============================================
# 21. SUID/SGID Binary Audit
# ============================================
print_status "Auditing and stripping unnecessary SUID/SGID bits..."
mkdir -p /var/log/hardening

find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null \
  > /var/log/hardening/suid-sgid-before.txt

STRIP_SUID=(
  /usr/bin/chfn
  /usr/bin/chsh
  /usr/bin/newgrp
  /usr/sbin/pppd
)
for bin in "${STRIP_SUID[@]}"; do
  if [[ -f "$bin" ]]; then
    chmod u-s,g-s "$bin" 2>/dev/null && echo "  Stripped: $bin"
  fi
done

find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null \
  > /var/log/hardening/suid-sgid-after.txt

# ============================================
# 22. Restrict Cron & At
# ============================================
print_status "Restricting cron and at to root only..."
echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow
chmod 600 /etc/cron.allow /etc/at.allow
rm -f /etc/cron.deny /etc/at.deny

# ============================================
# 23. DNS over TLS (systemd-resolved)
# ============================================
print_status "Configuring DNS over TLS..."
mkdir -p /etc/systemd/resolved.conf.d
cat << 'EOF' > /etc/systemd/resolved.conf.d/dns-over-tls.conf
[Resolve]
DNS=1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com
DNS=2606:4700:4700::1111#cloudflare-dns.com 2606:4700:4700::1001#cloudflare-dns.com
DNSOverTLS=yes
DNSSEC=allow-downgrade
EOF
systemctl restart systemd-resolved 2>/dev/null || true

# ============================================
# 24. Lynis Security Audit (baseline)
# ============================================
print_status "Running Lynis security audit (baseline)..."
mkdir -p /var/log/lynis
lynis audit system --no-colors --quiet > /var/log/lynis/baseline-$(date +%Y%m%d).log 2>&1 || true
LYNIS_SCORE=$(grep 'Hardening index' /var/log/lynis/baseline-*.log 2>/dev/null | tail -1 || echo "N/A")
print_status "Lynis baseline: $LYNIS_SCORE"

# ============================================
# 25. Helper: Enable Port 80 (Cloudflare Only)
# ============================================
cat << 'SCRIPT' > /usr/local/sbin/enable-http-cloudflare.sh
#!/usr/bin/env bash
set -e
echo "Enabling port 80 for Cloudflare IPs only..."
for cidr in \
  173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 \
  141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 \
  197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 \
  104.24.0.0/14 172.64.0.0/13 131.0.72.0/22; do
  ufw allow from "$cidr" to any port 80 proto tcp comment 'HTTP Cloudflare'
done
for cidr in \
  2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 \
  2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32; do
  ufw allow from "$cidr" to any port 80 proto tcp comment 'HTTP Cloudflare v6'
done
ufw reload
echo "Done. Port 80 now accepts traffic from Cloudflare only."
SCRIPT
chmod 700 /usr/local/sbin/enable-http-cloudflare.sh

# ============================================
# 26. Helper: Update Cloudflare IPs
# ============================================
cat << 'SCRIPT' > /usr/local/sbin/update-cloudflare-ips.sh
#!/usr/bin/env bash
set -e
echo "Fetching current Cloudflare IP ranges..."
V4=$(curl -sf https://www.cloudflare.com/ips-v4/)
V6=$(curl -sf https://www.cloudflare.com/ips-v6/)
if [[ -z "$V4" ]]; then
  echo "ERROR: Could not fetch Cloudflare IPs. Aborting."
  exit 1
fi

echo "Removing old Cloudflare rules..."
ufw status numbered | grep 'Cloudflare' | awk -F'[][]' '{print $2}' | sort -rn | while read -r num; do
  yes | ufw delete "$num"
done

echo "Adding updated Cloudflare IPv4 ranges for port 443..."
for cidr in $V4; do
  ufw allow from "$cidr" to any port 443 proto tcp comment 'HTTPS Cloudflare'
done
echo "Adding updated Cloudflare IPv6 ranges for port 443..."
for cidr in $V6; do
  ufw allow from "$cidr" to any port 443 proto tcp comment 'HTTPS Cloudflare v6'
done

HAS_HTTP=$(ufw status | grep -c '80/tcp.*Cloudflare' || true)
if [[ "$HAS_HTTP" -gt 0 ]]; then
  echo "Port 80 was open — re-adding with updated IPs..."
  for cidr in $V4; do
    ufw allow from "$cidr" to any port 80 proto tcp comment 'HTTP Cloudflare'
  done
  for cidr in $V6; do
    ufw allow from "$cidr" to any port 80 proto tcp comment 'HTTP Cloudflare v6'
  done
fi

ufw reload
echo "Cloudflare IP rules updated successfully."
SCRIPT
chmod 700 /usr/local/sbin/update-cloudflare-ips.sh

# ============================================
#  Summary
# ============================================
echo ""
echo "=============================================="
echo -e "${GREEN}  Server Hardening Complete${NC}"
echo "=============================================="
echo ""
echo "NETWORK:"
echo "  SSH:         Port 22 — Tailscale only (tailscale0 interface)"
echo "  Ports 8080-8081: Public (HTTP API, domain-fronted)"
echo "  Tailscale:   $TAILSCALE_IP"
echo "  HTTPS 443:   Cloudflare IPs only"
echo "  DNS:         Over TLS via Cloudflare (1.1.1.1)"
echo "  Everything:  Blocked by default"
echo ""
echo "SECURITY:"
echo "  Fail2Ban:    24h ban after 5 failed SSH attempts"
echo "  AppArmor:    Enforced"
echo "  Auditd:      Monitoring auth, SSH keys, config files"
echo "  AIDE:        File integrity monitoring (daily cron check)"
echo "  Kernel:      ASLR, SYN cookies, no pings, no redirects, ptrace locked"
echo "  SSH:         Key-only, strong ciphers, no forwarding, 3 max attempts"
echo "  Core dumps:  Disabled"
echo "  SUID/SGID:   Unnecessary bits stripped, full audit in /var/log/hardening/"
echo "  Cron/At:     Restricted to root only"
echo "  Rootkit:     rkhunter + chkrootkit installed (baseline captured)"
echo "  Lynis:       $LYNIS_SCORE"
echo "  Updates:     Automatic security patches (no auto-reboot)"
echo ""
echo "SERVICE USER:"
echo "  User:        $SVC_USER (run FastAPI and other apps as this user)"
echo "  Switch:      su - $SVC_USER"
echo "  Home:        /home/$SVC_USER"
echo "  Docker:      $SVC_USER added to docker group"
echo ""
echo "TOOLS:"
echo "  uv:          $HOME/.local/bin/uv"
echo "  Docker:      $(docker --version 2>/dev/null || echo 'installed')"
echo ""
echo -e "${YELLOW}IMPORTANT — READ THIS:${NC}"
echo "  SSH is now ONLY accessible via Tailscale."
echo "  Connect with:  ssh root@$TAILSCALE_IP"
echo "  Run services as '$SVC_USER', NEVER as root."
echo ""
echo -e "${YELLOW}MAINTENANCE:${NC}"
echo "  Enable HTTP:         /usr/local/sbin/enable-http-cloudflare.sh"
echo "  Update CF IPs:       /usr/local/sbin/update-cloudflare-ips.sh"
echo "  Rootkit scan:        rkhunter --check"
echo "  File integrity:      aide --check"
echo "  Lynis re-audit:      lynis audit system"
echo "  SUID audit log:      cat /var/log/hardening/suid-sgid-after.txt"
echo "  Audit SSH keys:      ausearch -k ssh_keys"
echo "  Audit config edits:  ausearch -k sshd_config"
echo ""
