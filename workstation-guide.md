# Linux Workstation Security and Privacy Guide

Last updated: 2026-11-12

## Contents

- [About this guide](#about-this-guide)
- [Basics and threat model](#basics-and-threat-model)
- [Hardware and firmware](#hardware-and-firmware)
- [Installation and disk encryption](#installation-and-disk-encryption)
- [System updates](#system-updates)
- [Users, sudo and authentication](#users-sudo-and-authentication)
- [Firewall](#firewall)
- [Services and attack surface](#services-and-attack-surface)
- [Kernel and system hardening](#kernel-and-system-hardening)
- [Mandatory access control](#mandatory-access-control)
- [Cloud access and credential hygiene](#cloud-access-and-credential-hygiene)
- [Network](#network)
- [Browsers and applications](#browsers-and-applications)
- [Screen lock, physical security and privacy](#screen-lock-physical-security-and-privacy)
- [Logging, auditing and integrity](#logging-auditing-and-integrity)
- [Backups](#backups)
- [Incident response and lost devices](#incident-response-and-lost-devices)
- [Compliance checklist](#compliance-checklist)
- [References and further reading](#references-and-further-reading)

## About this guide

This guide hardens individual Linux workstations that engineers use to reach our cloud infrastructure. It is modeled on [drduh/macOS-Security-and-Privacy-Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide): practical controls, the commands to apply them, and a command to verify each one.

A laptop with a valid SSO session, SSH agent and kubeconfig is effectively a privileged node of production. Most cloud breaches start on an endpoint, so the controls here focus on protecting credentials first and the OS second.

This guide is provided as is. Test changes on a non-critical machine before applying them to your daily driver.

### Supported distributions

| Family | Releases covered | Package manager | Default MAC | Default firewall |
| --- | --- | --- | --- | --- |
| Debian | 13 (trixie) | apt | AppArmor | none (install nftables or ufw) |
| Ubuntu | 24.04 LTS, 26.04 LTS | apt | AppArmor | ufw (inactive by default) |
| Fedora | 44, 45 | dnf5 | SELinux (enforcing) | firewalld |
| Arch Linux | rolling | pacman | none (opt-in AppArmor) | none (install nftables or ufw) |
| openSUSE | Leap 16.0, Tumbleweed | zypper | SELinux (new installs) | firewalld |

Only releases still receiving security updates are allowed to connect to cloud infrastructure. Debian 12, Ubuntu 22.04 and Fedora 43 are past or near end of standard support; plan upgrades now.

### How to read the commands

Commands are grouped by family. Where a step is identical everywhere, it is shown once.

- **Debian/Ubuntu** covers Debian, Ubuntu and their derivatives (Pop!\_OS, Linux Mint) unless noted.
- **Fedora** applies to Fedora Workstation and the Atomic desktops (Silverblue, Kinoite), except that Atomic uses `rpm-ostree` for packages.
- **Arch** applies to Arch Linux and close derivatives (EndeavourOS); Manjaro lags upstream and is not recommended.
- **openSUSE** applies to Leap 16.0 and Tumbleweed unless noted.

Run commands as your normal user; `sudo` is shown where root is needed. Values in angle brackets, such as `<corp-sso-url>`, are placeholders for your organization's values.

### Requirement levels

- **Required**: baseline every workstation must meet before connecting to cloud infrastructure. These appear in the compliance checklist at the end.
- **Recommended**: strong defaults that most users should adopt.
- **Optional**: higher-assurance options for users with elevated access or a higher threat model.

## Basics and threat model

The workstation's job is to keep cloud credentials out of an attacker's hands. Every control below maps to one of the threats in the table.

General practice, in priority order:

1. Keep the OS, firmware and applications patched, automatically where possible.
2. Encrypt the disk and lock the screen.
3. Keep long-lived secrets off the disk: use SSO, short-lived tokens and hardware-backed keys.
4. Run as a standard user and confine what you install.
5. Install software only from distribution repositories or vendors you can verify.
6. Report anything odd early. A lost laptop reported in an hour is an inconvenience; reported in a week it is an incident.

### Assets

List what is worth protecting, most valuable first:

- Cloud identity sessions: SSO browser cookies, `~/.aws/sso/cache`, `~/.config/gcloud`, `~/.azure`, `~/.kube/config` tokens.
- SSH private keys and agent sockets with access to bastions and hosts.
- Git credentials, signing keys and access to source repositories and CI/CD.
- Secrets in environment files, shell history, Terraform state and local databases.
- Customer data pulled to the laptop for debugging.

### Example threat model

| Adversary | Goal | Capabilities | Primary mitigations |
| --- | --- | --- | --- |
| Opportunistic thief | Resell the device, harvest whatever is on it | Steals a laptop left unattended or asleep | Full-disk encryption, auto screen lock, short idle timeout, report loss immediately |
| Commodity malware / infostealer | Steal session cookies and tokens to sell or use | Runs as your user after a malicious download, extension or package | Confinement (Flatpak, AppArmor/SELinux), short-lived creds, hardware-bound keys, EDR, browser extension allowlist |
| Supply-chain attacker | Pivot into the cloud via developer tooling | Malicious npm/PyPI/crate, compromised IDE extension or curl-to-bash script | Pin and verify dependencies, dev containers, no global installs as root, separate profile for untrusted code |
| Phishing / social engineering | Obtain SSO credentials or MFA approval | Fake login pages, MFA fatigue, "run this command" support scams | Phishing-resistant MFA (FIDO2/passkeys), never paste commands from chat, verify with security team |
| Network attacker | Intercept or tamper with traffic | Hostile Wi-Fi, rogue DHCP/DNS, captive portals | Corporate VPN/ZTNA, firewall, encrypted DNS, host key verification |
| Targeted / insider with physical access | Persistent access to a specific engineer | Evil-maid boot tampering, hardware implants, shoulder surfing | Secure Boot, firmware password, TPM-measured unlock, tamper-evident storage, power off when travelling |

Revisit the model when your role, access level or travel pattern changes. Engineers with production admin rights should apply the **Optional** controls as well.

### What this guide does not cover

- Hardening of cloud resources themselves, CI runners or servers.
- Fully managed corporate devices, which follow the IT build standard instead.
- Defending against a well-resourced adversary with prolonged physical access.

## Hardware and firmware

Use a machine with UEFI, TPM 2.0 and vendor firmware published to the [Linux Vendor Firmware Service](https://fwupd.org/) (LVFS). Without those, Secure Boot, measured unlock and firmware patching are not possible.

### Choosing hardware

- Prefer vendors that ship firmware through LVFS (Dell, Lenovo, HP, Framework and others) so updates arrive via `fwupd`.
- Avoid hardware whose vendor has stopped issuing firmware updates.
- A built-in keyboard and fingerprint reader reduce exposure to inline USB keyloggers and make frequent locking less painful.

### UEFI settings (Required)

In the firmware setup screen:

- Set a **supervisor/administrator password**, stored in your password manager.
- Enable **Secure Boot** in standard mode with the Microsoft and vendor keys. Do not use "setup mode" day to day.
- Enable the **TPM 2.0** (sometimes "PTT" on Intel or "fTPM" on AMD).
- Disable boot from USB/network, or require the supervisor password to change the boot order.
- Enable Thunderbolt/USB4 DMA protection ("Kernel DMA Protection" / IOMMU) if offered.
- Disable unused radios and ports (WWAN, legacy serial) if you never use them.

Verify Secure Boot and TPM from Linux:

```bash
mokutil --sb-state            # expect: SecureBoot enabled
bootctl status | grep -i 'secure boot'
ls /dev/tpmrm0 && systemd-analyze has-tpm2
```

### Secure Boot per distribution

- **Debian/Ubuntu, Fedora, openSUSE**: work with Secure Boot out of the box through the signed `shim`. Third-party kernel modules (NVIDIA, VirtualBox, VMware) must be signed with a Machine Owner Key (MOK); follow the prompt to enroll it at next boot rather than disabling Secure Boot.
- **Arch**: no signed shim is installed by default. Use [`sbctl`](https://github.com/Foxboron/sbctl) to create and enroll your own keys and sign the kernel or unified kernel image (UKI):

```bash
sudo pacman -S sbctl
sudo sbctl status                  # firmware must be in Setup Mode for enrollment
sudo sbctl create-keys
sudo sbctl enroll-keys -m          # -m keeps Microsoft keys for option ROMs
sudo sbctl sign -s /boot/vmlinuz-linux
sudo sbctl sign -s /boot/EFI/BOOT/BOOTX64.EFI
sudo sbctl verify
```

`sbctl` installs a pacman hook that re-signs files on kernel updates. Confirm `sbctl verify` is clean after each update.

### Firmware updates (Required)

`fwupd` is packaged on every supported distribution and updates UEFI, TPM, SSD, dock and Thunderbolt firmware.

```bash
# Debian/Ubuntu
sudo apt install fwupd
# Fedora
sudo dnf install fwupd
# Arch
sudo pacman -S fwupd
# openSUSE
sudo zypper install fwupd

fwupdmgr refresh
fwupdmgr get-updates
fwupdmgr update
fwupdmgr security        # Host Security ID (HSI) report
```

Aim for HSI level 2 or higher in `fwupdmgr security`. The report lists which firmware protections (Secure Boot, BIOS write protection, IOMMU, encrypted RAM) are missing.

If you use TPM-bound disk unlock, firmware updates change PCR measurements. Have your LUKS recovery key available before applying them (see Installation).

## Installation and disk encryption

Install from a verified image onto a LUKS2-encrypted disk. Full-disk encryption is **Required**; it is the only control that protects a stolen laptop that is powered off.

### Verify the installer image

Download the ISO, its checksum file and the checksum signature from the official site only. Verify the signature, then the checksum.

```bash
# Debian (keys: https://www.debian.org/CD/verify)
gpg --keyserver keyring.debian.org --recv-keys DF9B9C49EAA9298432589D76DA87E80D6294BE9B
gpg --verify SHA512SUMS.sign SHA512SUMS
sha512sum -c SHA512SUMS --ignore-missing

# Ubuntu (keys: https://ubuntu.com/tutorials/how-to-verify-ubuntu)
gpg --keyid-format long --keyserver hkp://keyserver.ubuntu.com --recv-keys 0x843938DF228D22F7B3742BC0D94AA3F0EFE21092
gpg --keyid-format long --verify SHA256SUMS.gpg SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing

# Fedora (keys: https://fedoraproject.org/security/)
curl -O https://fedoraproject.org/fedora.gpg
gpgv --keyring ./fedora.gpg Fedora-*-CHECKSUM
sha256sum -c Fedora-*-CHECKSUM --ignore-missing

# Arch (keys: https://archlinux.org/download/)
gpg --auto-key-locate clear,wkd -v --locate-external-key pierre@archlinux.org
gpg --verify archlinux-*-x86_64.iso.sig
sha256sum -c sha256sums.txt --ignore-missing

# openSUSE (keys: https://en.opensuse.org/openSUSE:Signing_Keys)
gpg --verify openSUSE-*.iso.sha256.asc openSUSE-*.iso.sha256
sha256sum -c openSUSE-*.iso.sha256
```

Confirm `Good signature` and that the key fingerprint matches the one published on the distribution's site, then `OK` for the ISO line. Key IDs above are current at time of writing; always cross-check against the linked page.

### Encrypt the disk (Required)

Use LUKS2 with the installer's encryption option and a strong passphrase (diceware, 6+ words).

| Distribution | Installer option |
| --- | --- |
| Debian | Partitioning: "Guided – use entire disk and set up encrypted LVM" |
| Ubuntu 24.04 / 26.04 | "Advanced features" → "Use LVM and encryption", or on 26.04 the TPM-backed full-disk encryption option |
| Fedora | Installation destination → "Encrypt my data" |
| Arch | Manual: `cryptsetup luksFormat --type luks2` before creating filesystems ([dm-crypt wiki](https://wiki.archlinux.org/title/Dm-crypt/Encrypting_an_entire_system)) |
| openSUSE | Agama/YaST storage settings → "Encrypt the system" |

On an existing unencrypted install, back up and reinstall. In-place encryption (`cryptsetup reencrypt --encrypt`) is possible but error-prone.

Verify:

```bash
lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINTS      # root and swap should sit under a 'crypt' device
sudo cryptsetup luksDump /dev/nvme0n1p3 | grep -E 'Version|PBKDF|Cipher'
# expect: Version 2, PBKDF argon2id, Cipher aes-xts-plain64
```

### Recovery key (Required)

Add a separate recovery key to a free LUKS slot and store it in your password manager or the escrow location IT designates. Never keep it on the laptop.

```bash
sudo systemd-cryptenroll /dev/nvme0n1p3 --recovery-key
```

### TPM2 or FIDO2 unlock (Optional)

Binding unlock to the TPM protects against an attacker who removes the disk, and lets you add a short PIN instead of a long passphrase. Binding to a FIDO2 key (YubiKey, Nitrokey) requires the token to be present at boot.

```bash
# TPM2 bound to Secure Boot state (PCR 7) with a PIN
sudo systemd-cryptenroll /dev/nvme0n1p3 --tpm2-device=auto --tpm2-pcrs=7 --tpm2-with-pin=yes
# or a FIDO2 token
sudo systemd-cryptenroll /dev/nvme0n1p3 --fido2-device=auto
```

Then add `tpm2-device=auto` or `fido2-device=auto` to the volume's options in `/etc/crypttab` and rebuild the initramfs.

- **Fedora, openSUSE**: dracut supports this directly. Run `sudo dracut -f`.
- **Arch**: use the systemd initramfs hooks (`systemd` and `sd-encrypt` in `/etc/mkinitcpio.conf`), then `sudo mkinitcpio -P`.
- **Debian**: the default initramfs-tools does not read these tokens. Install `dracut` and `systemd-cryptsetup`, then rebuild.
- **Ubuntu 26.04**: prefer the installer's TPM-backed FDE, which is managed from Security Center, over a manual setup.

Always keep a passphrase or recovery-key slot. TPM unlock without a PIN still lets anyone who steals the powered-off laptop boot to the login screen, so use a PIN on machines with production access.

### Swap, hibernation and temporary files

- Keep swap inside the encrypted volume, or use `zram` (default on Fedora) instead of a swap partition.
- Hibernation writes RAM, including tokens, to swap. Only enable it if swap is encrypted.
- Mount `/tmp` as `tmpfs` (default on Fedora, Arch and Debian 13) so temporary secrets do not persist.

## System updates

Install security updates automatically and reboot into new kernels within a few days. Unpatched browsers and kernels are the most common way an endpoint is compromised.

### Patch policy (Required)

| Update type | Install within | Notes |
| --- | --- | --- |
| Critical / actively exploited (browser, kernel, OpenSSH, sudo) | 72 hours | Reboot or restart the affected app the same day |
| Other security updates | 14 days | Automatic updates satisfy this |
| Distribution release upgrade | Before the current release reaches end of life | Machines on EOL releases lose cloud access |

Adjust the windows above to match your organization's vulnerability management policy.

### Debian/Ubuntu

```bash
sudo apt install unattended-upgrades apt-listchanges needrestart
sudo dpkg-reconfigure -plow unattended-upgrades   # answer Yes

# verify
systemctl list-timers apt-daily*
sudo unattended-upgrade --dry-run --debug | tail
```

By default only the `-security` pocket is applied automatically, which is the right setting for most users. Logs are in `/var/log/unattended-upgrades/`.

On Ubuntu LTS, [Livepatch](https://ubuntu.com/security/livepatch) applies critical kernel fixes without a reboot. It needs an Ubuntu Pro token (`sudo pro attach <token>`, then `sudo pro enable livepatch`). Livepatch does not replace reboots for other updates.

### Fedora

```bash
sudo dnf install dnf5-plugin-automatic
sudo cp /usr/share/dnf5/dnf5-plugins/automatic.conf /etc/dnf/automatic.conf
```

In `/etc/dnf/automatic.conf` set:

```ini
[commands]
upgrade_type = security
apply_updates = yes
```

```bash
sudo systemctl enable --now dnf5-automatic.timer
systemctl list-timers dnf5-automatic.timer
```

Fedora Atomic desktops (Silverblue, Kinoite) stage updates with `rpm-ostree`: set `AutomaticUpdatePolicy=stage` in `/etc/rpm-ostreed.conf`, then `sudo systemctl enable --now rpm-ostreed-automatic.timer`.

Upgrade to each new Fedora release within a month; each release gets about 13 months of updates.

### Arch

Arch has no supported unattended updates, because upgrades occasionally need manual steps.

- Run `sudo pacman -Syu` at least twice a week and immediately after critical advisories.
- Never do partial upgrades (`pacman -Sy <pkg>`).
- Subscribe to [Arch news](https://archlinux.org/news/) and [Arch security advisories](https://security.archlinux.org/).
- Use `arch-audit` to list installed packages with known vulnerabilities:

```bash
sudo pacman -S arch-audit
arch-audit --upgradable
```

Consider installing `linux-lts` as a fallback kernel. Treat AUR packages as untrusted code: read every PKGBUILD before building.

### openSUSE

```bash
# Leap: security and recommended patches
sudo zypper refresh && sudo zypper patch

# Tumbleweed: full distribution upgrade (never 'zypper up')
sudo zypper refresh && sudo zypper dup
```

Automate with `os-update`:

```bash
sudo zypper install os-update
sudo systemctl enable --now os-update.timer
```

Set the update command in `/etc/os-update.conf` to match your release (`dup` for Tumbleweed, patch-based for Leap). Snapper snapshots on Btrfs let you roll back a broken update from the boot menu.

### Reboots and restarts

A patched library or kernel only protects you after the process using it restarts.

```bash
# Debian/Ubuntu, Arch, openSUSE
sudo needrestart -r l          # Debian/Ubuntu, Arch
sudo zypper ps -s              # openSUSE
# Fedora
sudo dnf needs-restarting -r
# any: running kernel vs installed kernel
uname -r
```

Restart browsers when they prompt; reboot at least weekly.

### Third-party repositories

- Keep third-party repos to the minimum you need (VPN client, EDR agent, cloud CLIs).
- Use per-repo signing keys (`signed-by=` on Debian/Ubuntu; `gpgcheck=1` and `repo_gpgcheck=1` on Fedora/openSUSE). Never use `[trusted=yes]` or disable GPG checks.
- Do not pipe install scripts from the internet into a shell. Download, read, then run.

## Users, sudo and authentication

Use one personal account per person, no shared accounts, a locked root password, and a password prompt for every `sudo`. Anything running as your user can read your cloud tokens, so membership in root-equivalent groups matters as much as sudo.

### Account setup (Required)

- Use a unique login passphrase of at least 14 characters, not reused anywhere else.
- Lock the root account's password so root is reached only through `sudo`:

```bash
sudo passwd -S root      # 'L' or 'LK' means locked
sudo passwd -l root
```

- Ubuntu and Fedora lock root by default. Debian locks it only if you left the root password empty during install. openSUSE may set one depending on installer choices.
- On openSUSE, make `sudo` ask for your own password instead of root's, then lock root:

```bash
sudo zypper install sudo-policy-wheel-auth-self
sudo usermod -aG wheel $USER
```

### Root-equivalent groups

These groups grant root without a password prompt. Do not add your daily account to them:

| Group | Why it is root-equivalent | Alternative |
| --- | --- | --- |
| `docker` | Can mount `/` into a container | Rootless Podman or rootless Docker |
| `lxd` / `incus-admin` | Privileged containers | Use `sudo` when needed |
| `libvirt` | Can define VMs with host devices | `qemu:///session` user VMs |
| `disk` | Raw block device access | `udisksctl` for removable media |

```bash
id -nG    # review your groups
```

For higher assurance (Optional), use a separate admin account that holds `sudo`, and a daily account that does not, as the macOS guide recommends.

### sudo hardening (Recommended)

Create `/etc/sudoers.d/00-hardening` with `sudo visudo -f /etc/sudoers.d/00-hardening`:

```
Defaults timestamp_timeout=5
Defaults passwd_tries=3
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
```

- Never use `NOPASSWD` for a full shell or for editors, package managers or interpreters.
- Ubuntu 25.10 and later use `sudo-rs`, which supports a subset of sudoers options (it enables `use_pty` by default and logs to the journal). Check what is in use with `sudo --version`; `sudo.ws` remains installable if you need the full option set.
- Review sudo activity with `journalctl _COMM=sudo` or `/var/log/sudo.log`.

### Password quality and lockout (Recommended)

Set a minimum length and lock out repeated failures to slow down an attacker at the lock screen.

```ini
# /etc/security/pwquality.conf
minlen = 14
dictcheck = 1
enforce_for_root

# /etc/security/faillock.conf
deny = 5
unlock_time = 900
```

- **Fedora**: `sudo authselect enable-feature with-faillock` and `with-pwquality` is on by default.
- **Debian/Ubuntu**: `sudo apt install libpam-pwquality`; faillock requires adding `pam_faillock.so` lines to `/etc/pam.d/common-auth` (see `man pam_faillock`).
- **Arch**: `pam_faillock` is enabled by default in `system-auth`; add `password required pam_pwquality.so` to `/etc/pam.d/passwd` after installing `libpwquality`.
- **openSUSE**: install `pam_pwquality` and enable with `pam-config -a --pwquality`.

### Hardware security keys for login and sudo (Optional)

`pam_u2f` requires a touch of a FIDO2 key (YubiKey, Nitrokey, SoloKey) in addition to, or instead of, the password.

```bash
# Debian/Ubuntu: libpam-u2f | Fedora: pam-u2f | Arch: pam-u2f | openSUSE: pam_u2f
mkdir -p ~/.config/Yubico
pamu2fcfg > ~/.config/Yubico/u2f_keys          # register primary key
pamu2fcfg -n >> ~/.config/Yubico/u2f_keys       # register backup key
```

Add as the first `auth` line of `/etc/pam.d/sudo` (and your display manager's PAM file for login):

```
auth required pam_u2f.so cue
```

On Fedora use `sudo authselect enable-feature with-pam-u2f-2fa` instead of editing PAM files. Keep a root shell open in another terminal while testing so a mistake cannot lock you out. Register a backup key and store it separately.

### Password manager (Required)

Store your login passphrase, LUKS recovery key, firmware password and all web credentials in the organization-approved password manager. Never store cloud access keys or SSH private keys in plain files or browser autofill.

## Firewall

Enable a host firewall that drops all unsolicited inbound traffic (**Required**). A workstation should accept no inbound connections on untrusted networks; outbound filtering is optional. All three front ends below write nftables rules in the kernel, so use exactly one.

| Distribution | Use | Enabled by default |
| --- | --- | --- |
| Fedora, openSUSE | firewalld | Yes |
| Ubuntu | ufw | Installed, inactive |
| Debian, Arch | ufw or plain nftables | No |

### firewalld (Fedora, openSUSE)

The default zones allow some inbound services. Fedora Workstation's `FedoraWorkstation` zone opens ports 1025–65535 and SSH; openSUSE's `public` zone allows SSH and Cockpit. Tighten them:

```bash
sudo firewall-cmd --get-active-zones
sudo firewall-cmd --list-all

# Option A (strictest): drop all unsolicited inbound on every interface
sudo firewall-cmd --set-default-zone=drop

# Option B: use 'public' and remove the inbound services you don't need
sudo firewall-cmd --set-default-zone=public
sudo firewall-cmd --permanent --zone=public --remove-service={ssh,cockpit,mdns}
sudo firewall-cmd --reload
sudo firewall-cmd --list-all       # expect: services: dhcpv6-client only
```

Option A can break DHCPv6 and some IPv6 networks; if IPv6 connectivity fails, use option B.

If you change the default zone, also check NetworkManager has not pinned a connection to another zone: `nmcli -f NAME,CONNECTION.ZONE connection show` (empty means default).

### ufw (Ubuntu, Debian, Arch)

```bash
# Debian: sudo apt install ufw | Arch: sudo pacman -S ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw logging low
sudo ufw enable
sudo systemctl enable ufw          # Arch: start at boot
sudo ufw status verbose
```

Add only narrowly-scoped exceptions, for example KDE Connect on a home subnet: `sudo ufw allow from 192.168.1.0/24 to any port 1714:1764 proto tcp`.

### Plain nftables (Debian, Arch)

For a minimal policy without a front end, write `/etc/nftables.conf`:

```
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;
    ct state established,related accept
    ct state invalid drop
    iif lo accept
    meta l4proto { icmp, ipv6-icmp } accept
    udp dport 68 accept           # DHCPv4 client
    udp dport 546 accept          # DHCPv6 client
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
  }
  chain output {
    type filter hook output priority filter; policy accept;
  }
}
```

```bash
sudo nft -c -f /etc/nftables.conf     # syntax check
sudo systemctl enable --now nftables
sudo nft list ruleset
```

Container engines and libvirt add their own rules; if you run Docker or VMs, prefer firewalld or ufw, which coexist with them more predictably.

### Verify nothing is listening

```bash
sudo ss -tulpn | grep -v '127.0.0.\|\[::1\]'
```

Every remaining line is a service reachable from the network if the firewall fails. Investigate each one (see Services).

### Outbound filtering (Optional)

[OpenSnitch](https://github.com/evilsocket/opensnitch) is an application-level firewall similar to Little Snitch on macOS. It prompts per process for outbound connections and is useful for spotting unexpected callbacks from tools and dependencies. It is packaged for Debian, Ubuntu, Fedora, Arch and openSUSE.

## Services and attack surface

Disable network-facing services you do not use. Every daemon removed is one less thing to patch and one less way in if the firewall is misconfigured.

### Review what is running

```bash
systemctl list-units --type=service --state=running
systemctl list-unit-files --state=enabled
systemctl --user list-units --type=service --state=running
sudo ss -tulpn
```

### Common services to disable

| Service | Unit | Purpose | Disable unless |
| --- | --- | --- | --- |
| SSH server | `ssh` (Debian/Ubuntu), `sshd` (others) | Inbound shell | You need inbound SSH to the laptop (rarely justified) |
| Avahi / mDNS | `avahi-daemon.service` and `.socket` | Zeroconf discovery, advertises hostname | You use network printers or casting via discovery |
| CUPS | `cups.service`, `cups-browsed.service` | Printing | You print; always disable `cups-browsed` |
| Cockpit | `cockpit.socket` | Web admin on port 9090 | Never needed on a laptop |
| rpcbind / NFS | `rpcbind.service`, `.socket` | NFS client support | You mount NFS shares |
| Bluetooth | `bluetooth.service` | Peripherals | You use Bluetooth devices |
| ModemManager | `ModemManager.service` | WWAN modems | You use a cellular modem |

```bash
sudo systemctl disable --now avahi-daemon.service avahi-daemon.socket
sudo systemctl disable --now cups-browsed.service
sudo systemctl disable --now cockpit.socket 2>/dev/null
# if no inbound SSH is needed:
sudo systemctl disable --now ssh.service sshd.service 2>/dev/null
```

`cups-browsed` had a critical remote-code-execution chain disclosed in 2024 (CVE-2024-47176 and related); there is no reason to run it on a workstation.

If you must run `sshd`, allow keys only and restrict who can log in:

```
# /etc/ssh/sshd_config.d/10-hardening.conf
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers <your-user>
```

### Remove unneeded software

Uninstall packages you installed once and no longer use, especially servers, remote-desktop tools and old SDKs.

```bash
# Debian/Ubuntu
sudo apt autoremove --purge
# Fedora
sudo dnf autoremove
# Arch: orphans
pacman -Qdtq | sudo pacman -Rns -
# openSUSE
sudo zypper packages --unneeded
```

### USB and Thunderbolt devices (Optional)

[USBGuard](https://usbguard.github.io/) blocks USB devices that are not on an allowlist, which defends against malicious HID devices ("rubber duckies") plugged in while you are away. It is packaged as `usbguard` on all five distributions.

```bash
sudo usbguard generate-policy > /tmp/rules.conf     # snapshot currently attached devices
sudo install -m 0600 /tmp/rules.conf /etc/usbguard/rules.conf
sudo systemctl enable --now usbguard
usbguard list-devices
usbguard allow-device <id> -p                         # permanently allow a new device
```

Generate the policy with your keyboard and dock attached, or you may lock yourself out of input devices.

Thunderbolt devices are authorized through `bolt` (GNOME and KDE show a prompt). Keep the security level at `user` or `secure`, check with `boltctl domains`, and only authorize docks you own.

## Kernel and system hardening

Apply a small set of sysctl, module and mount settings that close common local privilege escalation and network tricks without breaking desktop use (**Recommended**). Settings that commonly break tools are marked.

### sysctl settings

Create `/etc/sysctl.d/90-workstation-hardening.conf`:

```ini
# Hide kernel pointers and logs from unprivileged users
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
# Restrict BPF and perf to root
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.perf_event_paranoid = 2
# Only parents may ptrace children (1); use 2 to require root (breaks gdb/strace attach)
kernel.yama.ptrace_scope = 1
# No kexec of a new kernel at runtime; restrict SysRq
kernel.kexec_load_disabled = 1
kernel.sysrq = 0
# Filesystem protections
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
dev.tty.ldisc_autoload = 0
# Network: ignore redirects and source routing, anti-spoofing
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
```

```bash
sudo sysctl --system
sysctl kernel.kptr_restrict kernel.yama.ptrace_scope     # verify
```

Notes:

- If your VPN client drops traffic after this change, set `rp_filter = 2` (loose) instead of 1.
- Do **not** disable unprivileged user namespaces globally: browsers, Flatpak and rootless containers rely on them for sandboxing. Ubuntu 24.04+ already restricts them per application through AppArmor.

### Kernel lockdown

With Secure Boot on, Debian, Ubuntu, Fedora and openSUSE kernels enter lockdown `integrity` mode automatically. This blocks unsigned modules and writes to kernel memory, even by root.

```bash
cat /sys/kernel/security/lockdown        # expect: [integrity] or [confidentiality]
```

On Arch, lockdown is opt-in: add `lockdown=integrity` to the kernel command line (Optional). It will refuse unsigned out-of-tree modules, so sign DKMS modules (NVIDIA, VirtualBox) first. `linux-hardened` is an alternative kernel with more aggressive defaults.

### Kernel command line (Optional)

These parameters harden memory allocation with a small performance cost:

```
init_on_alloc=1 init_on_free=1 slab_nomerge page_alloc.shuffle=1 randomize_kstack_offset=on vsyscall=none debugfs=off
```

| Distribution | How to add |
| --- | --- |
| Debian/Ubuntu | Append to `GRUB_CMDLINE_LINUX_DEFAULT` in `/etc/default/grub`, then `sudo update-grub` |
| Fedora | `sudo grubby --update-kernel=ALL --args="..."` |
| Arch | Edit your boot loader entry or `/etc/kernel/cmdline` for UKIs, then regenerate |
| openSUSE | GRUB: edit `/etc/default/grub` then `sudo grub2-mkconfig -o /boot/grub2/grub.cfg`; systemd-boot: edit `/etc/kernel/cmdline` then `sudo sdbootutil update-all-entries` |

Verify with `cat /proc/cmdline` after reboot.

### Disable rarely used kernel modules

Create `/etc/modprobe.d/workstation-hardening.conf` to stop obscure protocols and DMA-capable FireWire from auto-loading:

```
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install firewire-core /bin/false
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
```

Remove a line if you need that module (for example `sctp` for some telecom work).

### Mount options

- `/dev/shm`: mount with `nodev,nosuid,noexec`.
- `/tmp`: `nodev,nosuid` at minimum; `noexec` is stricter but breaks some installers and build tools.

```
# /etc/fstab
tmpfs  /dev/shm  tmpfs  defaults,nodev,nosuid,noexec  0 0
```

Verify with `findmnt /dev/shm /tmp`.

### Core dumps

Crash dumps of browsers, cloud CLIs or `ssh-agent` can contain tokens and keys. Disable storing them:

```ini
# /etc/systemd/coredump.conf.d/50-disable.conf
[Coredump]
Storage=none
ProcessSizeMax=0
```

```bash
sudo systemctl daemon-reload
coredumpctl list      # should stay empty after future crashes
```

## Mandatory access control

Keep the distribution's mandatory access control (MAC) framework enabled and enforcing (**Required** where it ships by default). AppArmor and SELinux confine services and some applications so a compromised process cannot read everything your user can.

| Distribution | Framework | Default state | Check |
| --- | --- | --- | --- |
| Debian, Ubuntu | AppArmor | Enforcing for shipped profiles | `sudo aa-status` |
| Fedora | SELinux (targeted) | Enforcing | `getenforce` |
| openSUSE Leap 16.0, new Tumbleweed installs | SELinux (targeted) | Enforcing | `getenforce` |
| openSUSE Leap 15.6, older Tumbleweed installs | AppArmor | Enforcing | `sudo aa-status` |
| Arch | None | Off | Enable AppArmor (below) |

### SELinux (Fedora, openSUSE)

```bash
getenforce                         # expect: Enforcing
sestatus
grep ^SELINUX= /etc/selinux/config # expect: SELINUX=enforcing
```

Never set `SELINUX=disabled` or `permissive` system-wide to make an app work. Investigate the denial instead:

```bash
sudo ausearch -m AVC,USER_AVC -ts recent
sudo sealert -a /var/log/audit/audit.log      # Fedora: setroubleshoot-server
# most fixes are a boolean or a file label:
getsebool -a | grep <keyword>
sudo restorecon -Rv <path>
# last resort: make only one domain permissive
sudo semanage permissive -a <domain_t>
```

If you moved `/home` or created directories outside standard paths, relabel with `sudo restorecon -Rv /home`.

### AppArmor (Debian, Ubuntu, older openSUSE)

```bash
sudo aa-status        # profiles loaded, how many in enforce vs complain mode
```

- Do not run `aa-teardown` or disable `apparmor.service`.
- To debug one application, switch only its profile to complain mode: `sudo aa-complain /etc/apparmor.d/<profile>`, then back with `aa-enforce`.
- Denials appear in `journalctl -k | grep apparmor="DENIED"`.
- Ubuntu 24.04+ uses AppArmor to restrict unprivileged user namespaces. If an AppImage or self-built Electron app fails to start, prefer a packaged or Flatpak version over disabling the restriction.

### Enabling AppArmor on Arch (Recommended)

```bash
sudo pacman -S apparmor
# add to the kernel command line, then regenerate boot entries:
#   lsm=landlock,lockdown,yama,integrity,apparmor,bpf
sudo systemctl enable apparmor.service
# after reboot:
cat /sys/kernel/security/lsm
sudo aa-status
```

Arch ships few profiles. The [apparmor.d](https://github.com/roddhjav/apparmor.d) project provides 1,500+ profiles for desktop systems; start it in complain mode and review denials before enforcing.

## Cloud access and credential hygiene

No long-lived cloud credential may be stored in plain text on a workstation (**Required**). Authenticate through SSO with phishing-resistant MFA, use tokens that expire within hours, and keep SSH keys on hardware or behind a passphrase. This section matters more than any OS setting: infostealer malware targets exactly these files.

### Where credentials live, and what is allowed

| Tool | Location | Allowed | Not allowed |
| --- | --- | --- | --- |
| AWS CLI / SDKs | `~/.aws/config`, `~/.aws/sso/cache/` | IAM Identity Center (SSO) profiles | `aws_access_key_id` in `~/.aws/credentials` |
| gcloud | `~/.config/gcloud/` | User login, service account impersonation | Downloaded service account JSON keys |
| Azure CLI | `~/.azure/` | `az login` with Entra ID, device code only when no browser | Service principal secrets in env files |
| kubectl | `~/.kube/config` | `exec` credential plugins (EKS, GKE, kubelogin) | Static `token:` or `client-key-data:` entries |
| Terraform | Remote backend | State in an encrypted remote backend | Local `terraform.tfstate` with secrets |
| Docker / registries | `~/.docker/config.json` | `credsStore` using Secret Service | Base64 `auths` entries |
| Git hosting | Keyring / `gh` | `credential.helper libsecret`, `gh auth login` | `credential.helper store` (plain text) |

### AWS

```bash
aws configure sso          # creates an sso-session and profile in ~/.aws/config
aws sso login --profile <profile>
aws sts get-caller-identity --profile <profile>
aws sso logout             # end of day or when leaving the machine
```

If you have legacy access keys, delete them in IAM and remove `~/.aws/credentials`. Where a long-lived key is unavoidable (approved exception), store it in the system keyring through a `credential_process` helper, never in the file.

### Google Cloud

```bash
gcloud auth login
gcloud config set auth/impersonate_service_account <sa>@<project>.iam.gserviceaccount.com
gcloud auth application-default login --impersonate-service-account <sa>@<project>.iam.gserviceaccount.com
```

Application Default Credentials are a refresh token stored in `~/.config/gcloud/application_default_credentials.json`. Revoke them when a task is done with `gcloud auth application-default revoke`.

### Azure

```bash
az login
az account show
az logout
```

The Azure CLI's token cache in `~/.azure` grants access while valid. Keep the directory at mode `700` and log out on shared or travel machines.

### Kubernetes

Use the provider's exec plugin so kubeconfig holds no secrets:

```bash
aws eks update-kubeconfig --name <cluster> --profile <profile>
gcloud container clusters get-credentials <cluster> --region <region>   # uses gke-gcloud-auth-plugin
az aks get-credentials -n <cluster> -g <rg> && kubelogin convert-kubeconfig -l azurecli

# verify no embedded secrets
grep -nE 'token:|client-key-data:|password:' ~/.kube/config
```

Set a distinct context name per environment and show it in your prompt to avoid running commands against production by mistake.

### SSH

Prefer cloud-native session access (AWS Systems Manager Session Manager, GCP IAP TCP forwarding, Azure Bastion) or short-lived SSH certificates from the organization's CA over static keys. When you do use keys:

```bash
# FIDO2 hardware-backed key: private key never leaves the token
ssh-keygen -t ed25519-sk -O resident -O verify-required -C "$USER@laptop-$(date +%Y)"
# no hardware key: ed25519 with a strong passphrase
ssh-keygen -t ed25519 -a 100 -C "$USER@laptop-$(date +%Y)"

# load into the agent for 8 hours, confirm each use
ssh-add -c -t 8h ~/.ssh/id_ed25519
```

Baseline `~/.ssh/config`:

```
Host *
  IdentitiesOnly yes
  AddKeysToAgent yes
  ForwardAgent no
  ForwardX11 no
  HashKnownHosts yes
  StrictHostKeyChecking ask
  UpdateHostKeys yes
  ServerAliveInterval 60

Host bastion
  HostName bastion.<corp-domain>
  User <you>

Host *.internal 10.*
  ProxyJump bastion
```

- Never enable `ForwardAgent` to shared hosts; anyone with root there can use your agent. Use `ProxyJump` instead.
- Verify host key fingerprints on first connection against the published list or SSH certificates.
- One key per device. Revoke a device's key when the device is retired or lost.

### Git

```bash
git config --global credential.helper libsecret     # Debian/Ubuntu: build from git contrib; or use the 'gh' helper
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519_sk.pub
git config --global commit.gpgsign true
```

Install a pre-commit secret scanner (gitleaks or trufflehog) in repositories that touch infrastructure.

### Secrets in files, shells and env vars

- Fetch secrets at runtime from the organization's secrets manager (for example `vault kv get`, `op run --`, `aws secretsmanager get-secret-value`) instead of keeping `.env` files.
- Keep secrets out of shell history: in `~/.bashrc` set `HISTCONTROL=ignoreboth` and prefix sensitive commands with a space; zsh users set `setopt HIST_IGNORE_SPACE`.
- Lock down credential directories:

```bash
chmod 700 ~/.ssh ~/.aws ~/.azure ~/.kube ~/.config/gcloud 2>/dev/null
chmod 600 ~/.ssh/config ~/.kube/config 2>/dev/null
```

- Scan your home directory monthly for stray secrets:

```bash
trufflehog filesystem ~ --only-verified
```

### Separate contexts

- Use a dedicated browser profile for cloud consoles and SSO, with no extensions beyond the password manager.
- Run untrusted code (interview exercises, random GitHub repos, new dependencies) in a dev container or VM that has no access to `~/.aws`, `~/.ssh` or `~/.kube`.

## Network

Reach cloud infrastructure only through the corporate VPN or zero-trust access client (**Required**), and treat every other network as hostile. All five distributions use NetworkManager on the desktop, so the settings below apply everywhere.

### VPN and zero-trust access

- Install the approved client from the vendor's signed repository, not a third-party AUR or COPR build, unless IT has approved it.
- Connect before opening any cloud console, SSH session or `kubectl`. If the client supports "always-on" or a kill switch, enable it.
- For self-managed WireGuard tunnels, keep private keys mode `600` and owned by root: `sudo chmod 600 /etc/wireguard/*.conf`.
- Check for leaks while connected: `ip route`, `resolvectl status`, and confirm internal names resolve only through the VPN's DNS.

### Wi-Fi

- Prefer WPA3 or WPA2/WPA3-Enterprise. Forget open networks after use: `nmcli connection delete <name>`.
- On captive portals, sign in, then connect the VPN immediately. Do not log in to anything else first.
- Turn off Bluetooth and Wi-Fi Direct when not in use.

### MAC address and hostname privacy

Randomize the Wi-Fi MAC while scanning and use a per-network stable random MAC when connected. Create `/etc/NetworkManager/conf.d/00-privacy.conf`:

```ini
[device]
wifi.scan-rand-mac-address=yes

[connection]
wifi.cloned-mac-address=stable
ethernet.cloned-mac-address=stable
ipv6.ip6-privacy=2
```

```bash
sudo systemctl restart NetworkManager
ip link show <wifi-interface>      # address should differ from 'permaddr'
```

If a corporate network uses MAC-based registration (802.1X or NAC), set `wifi.cloned-mac-address=permanent` for that connection only.

Use a generic hostname that does not contain your name, and stop sending it in DHCP on public networks:

```bash
sudo hostnamectl set-hostname laptop-<asset-tag>
nmcli connection modify <public-wifi> ipv4.dhcp-send-hostname no ipv6.dhcp-send-hostname no
```

### Encrypted DNS

When off VPN, encrypt DNS to stop on-path snooping and tampering. Use the organization's protective DNS resolver if one is provided; otherwise a filtering public resolver.

`systemd-resolved` is the default on Ubuntu and Fedora. On Debian, Arch and openSUSE, install or enable it first (`sudo systemctl enable --now systemd-resolved` and link `/etc/resolv.conf` to `/run/systemd/resolve/stub-resolv.conf`).

```ini
# /etc/systemd/resolved.conf.d/10-dot.conf
[Resolve]
DNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net 2620:fe::fe#dns.quad9.net
DNSOverTLS=opportunistic
DNSSEC=allow-downgrade
```

```bash
sudo systemctl restart systemd-resolved
resolvectl status | grep -E 'DNS over TLS|DNSSEC|Current DNS'
```

`DNSOverTLS=yes` is stricter but breaks captive portals. The VPN client should still push per-link DNS for internal zones; verify with `resolvectl status <vpn-interface>`.

### Hosts-file blocklists (Optional)

Append a maintained list such as [StevenBlack/hosts](https://github.com/StevenBlack/hosts) to `/etc/hosts` to block known malware and tracking domains. Review it after each update and keep `127.0.0.1 localhost` intact.

### Trusted certificate authorities

A CA added to the system store can intercept all TLS traffic, including cloud API calls. Review locally added anchors:

| Distribution | Local CA directory | Rebuild command |
| --- | --- | --- |
| Debian/Ubuntu | `/usr/local/share/ca-certificates/` | `sudo update-ca-certificates` |
| Fedora | `/etc/pki/ca-trust/source/anchors/` | `sudo update-ca-trust` |
| Arch | `/etc/ca-certificates/trust-source/anchors/` | `sudo trust extract-compat` |
| openSUSE | `/etc/pki/trust/anchors/` | `sudo update-ca-certificates` |

```bash
trust list --filter=ca-anchors | grep label | sort | less
```

Remove any CA you did not install deliberately or that IT did not issue. Report unknown CAs to the security team.

## Browsers and applications

The browser holds your SSO session, which is worth more to an attacker than any password. Keep it current, keep extensions to an allowlist, and make sure its cookie store is encrypted by a keyring.

### Browser choice and installation

- Use Firefox, Google Chrome or Chromium from the distribution's repository or the vendor's signed repository. Ubuntu's Firefox snap and Mozilla's official Flatpak are also acceptable.
- Browsers update every few weeks. Restart when prompted; a pending update does nothing until you do.
- Use separate profiles: one for SSO and cloud consoles, one for general browsing. Firefox Multi-Account Containers achieve similar separation.

### Keyring-encrypted cookie storage (Required)

Chrome and Chromium on Linux encrypt saved passwords and cookies with a key held in the desktop keyring (GNOME Keyring or KWallet). If no keyring is available they fall back to a fixed, publicly known key, so any malware can decrypt session cookies.

- Use a full GNOME or KDE session, or start `gnome-keyring-daemon` in other window managers.
- Never launch Chromium-based browsers with `--password-store=basic`.
- Check that `secret-tool search --all xdg:schema chrome_libsecret_os_crypt_password_v2` (or `..._v1`) returns an entry after the browser has run.

### Extensions

A malicious or hijacked extension can read every page, including cloud consoles. Allow only extensions approved by the organization (password manager, SSO plug-in, an ad blocker such as uBlock Origin).

Enforce an allowlist with managed policies:

```json
// Chrome: /etc/opt/chrome/policies/managed/extensions.json
// Chromium: /etc/chromium/policies/managed/extensions.json
{
  "ExtensionInstallBlocklist": ["*"],
  "ExtensionInstallAllowlist": ["<extension-id-1>", "<extension-id-2>"],
  "PasswordManagerEnabled": false
}
```

```json
// Firefox: /etc/firefox/policies/policies.json
{
  "policies": {
    "ExtensionSettings": {
      "*": { "installation_mode": "blocked" },
      "<addon-id>@example": { "installation_mode": "allowed" }
    },
    "DisableTelemetry": true,
    "PasswordManagerEnabled": false
  }
}
```

Verify at `chrome://policy` or `about:policies`.

### Sandboxed desktop applications

- Prefer Flatpak apps from Flathub's verified publishers, or Ubuntu snaps with strict confinement, for chat, media and other non-system tools.
- Review and reduce Flatpak permissions; the riskiest are `filesystem=home`, `filesystem=host` and `talk-name=org.freedesktop.Flatpak`:

```bash
flatpak info --show-permissions <app-id>
flatpak override --user --nofilesystem=home <app-id>
```

- Flatseal provides a graphical view of the same settings.
- AppImages and downloaded binaries run unsandboxed with full access to your home directory. Avoid them, or run them inside a VM.

### Developer tooling

Developer tools run with your full user rights and are a common supply-chain target.

- **IDEs**: install extensions only from verified publishers and keep VS Code's Workspace Trust enabled. Open unfamiliar repositories in Restricted Mode.
- **Language package managers**: never install with `sudo` (`sudo pip`, `sudo npm -g`). Use per-project environments and lockfiles with hashes (`pip install --require-hashes`, `npm ci`).
- **Containers**: use rootless Podman (default on Fedora and openSUSE) or rootless Docker. Never mount `~/.aws`, `~/.ssh` or `~/.kube` into containers running third-party images.
- **Install scripts**: download, read, then run. Avoid `curl ... | sh`.
- **AI coding agents and MCP servers**: run them in a dev container or with an explicit allowlist of directories and commands, since they can read your credentials and execute code.

## Screen lock, physical security and privacy

Lock the screen automatically after at most 5 minutes idle and immediately on suspend or lid close (**Required**). An unlocked laptop bypasses every other control in this guide.

### GNOME (Ubuntu, Fedora, Debian, openSUSE default)

```bash
gsettings set org.gnome.desktop.session idle-delay 300
gsettings set org.gnome.desktop.screensaver lock-enabled true
gsettings set org.gnome.desktop.screensaver lock-delay 0
gsettings set org.gnome.desktop.notifications show-in-lock-screen false
```

To enforce these system-wide so users cannot loosen them, create `/etc/dconf/db/local.d/00-screenlock` with the same keys, list them in `/etc/dconf/db/local.d/locks/screenlock`, and run `sudo dconf update`. On Debian, also create `/etc/dconf/profile/user` containing `user-db:user` and `system-db:local`.

### KDE Plasma

```bash
kwriteconfig6 --file kscreenlockerrc --group Daemon --key Autolock true
kwriteconfig6 --file kscreenlockerrc --group Daemon --key Timeout 5
kwriteconfig6 --file kscreenlockerrc --group Daemon --key LockOnResume true
kwriteconfig6 --file kscreenlockerrc --group Daemon --key LockGrace 0
```

### Other window managers

Use `swayidle` with `swaylock` (Wayland) or `xss-lock` with `i3lock` (X11), and lock on `before-sleep`. Test with `loginctl lock-session`.

Bind a keyboard shortcut for locking (Super+L is the GNOME and KDE default) and use it every time you step away.

### Physical security

- Suspend keeps the disk encryption key in RAM. **Power off** before travel, border crossings and leaving the laptop in a hotel or car.
- Keep the laptop in your custody in public places. Use a privacy screen filter if you work on cloud consoles in public.
- Do not plug in unknown USB devices or charge from public USB ports without a data blocker.
- Optionally apply tamper-evident seals or glitter nail polish to case screws and check them after the device has been out of your sight.

### Crash reports and telemetry

Crash reports can contain process memory, including tokens. Disable automatic crash reporting, and opt out of telemetry you do not need.

| Distribution | Component | Disable |
| --- | --- | --- |
| Ubuntu | Apport crash reports | Set `enabled=0` in `/etc/default/apport`; `sudo systemctl disable --now apport` |
| Ubuntu | System diagnostics report | Settings → Privacy & Security → Diagnostics → Never |
| Debian | popularity-contest | `sudo dpkg-reconfigure popularity-contest` → No |
| Fedora | ABRT auto-reporting | `sudo abrt-auto-reporting disabled` |
| Fedora | DNF "countme" counter | Set `countme=0` in `/etc/yum.repos.d/*.repo` (optional; anonymous) |
| Arch | pkgstats | `sudo pacman -Rns pkgstats` if installed |
| openSUSE | none by default | No action |

Developer and cloud tools also collect usage data:

```bash
gcloud config set disable_usage_reporting true
az config set core.collect_telemetry=false
export DOTNET_CLI_TELEMETRY_OPTOUT=1   # add to your shell profile
export SAM_CLI_TELEMETRY=0
```

In VS Code, set `"telemetry.telemetryLevel": "off"`.

## Logging, auditing and integrity

Keep enough local evidence to answer "what touched my credentials, and when" after a suspected compromise, and run the organization's endpoint agent if one is mandated.

### Endpoint agent (Required if mandated)

Install the organization's EDR or device-posture agent (for example CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint, Elastic Defend, or osquery/Fleet). Check the vendor's Linux support matrix before choosing a distribution: rolling releases (Arch, Tumbleweed) and brand-new kernels are often unsupported, which may make Debian, Ubuntu LTS or Fedora the practical choice.

### Persistent journal

Fedora, Ubuntu, Debian 12+, Arch and openSUSE keep the journal on disk by default. Confirm and cap its size:

```bash
ls -d /var/log/journal && journalctl --disk-usage
```

```ini
# /etc/systemd/journald.conf.d/50-size.conf
[Journal]
Storage=persistent
SystemMaxUse=1G
```

### auditd rules (Recommended)

The Linux audit framework records security-relevant events independently of application logs.

```bash
# Debian/Ubuntu: sudo apt install auditd | Fedora: preinstalled | Arch: sudo pacman -S audit | openSUSE: sudo zypper install audit
sudo systemctl enable --now auditd
```

Create `/etc/audit/rules.d/50-workstation.rules`, replacing `<user>`:

```
# privilege and identity changes
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
# kernel modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
# commands run as root by a logged-in user
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k root_exec
# reads of cloud credentials and SSH keys
-w /home/<user>/.aws -p r -k cloud_creds
-w /home/<user>/.config/gcloud -p r -k cloud_creds
-w /home/<user>/.azure -p r -k cloud_creds
-w /home/<user>/.kube -p r -k cloud_creds
-w /home/<user>/.ssh -p r -k ssh_keys
```

```bash
sudo augenrules --load
sudo auditctl -l
# which programs read your cloud credentials?
sudo ausearch -k cloud_creds -i | grep -o 'exe=[^ ]*' | sort | uniq -c | sort -rn
```

Expect only `aws`, `gcloud`, `python`, `kubectl`, your IDE and similar. An unfamiliar binary reading `~/.aws` or `~/.ssh` is worth reporting.

### Persistence locations to review

Malware on Linux most often persists through user-level autostart. Review these monthly:

```bash
ls ~/.config/autostart/ /etc/xdg/autostart/
systemctl --user list-unit-files --state=enabled
ls ~/.config/systemd/user/
systemctl list-timers --all
crontab -l; sudo ls /etc/cron.d/ /var/spool/cron/ 2>/dev/null
grep -n -E 'curl|wget|base64|nc |/tmp/' ~/.bashrc ~/.zshrc ~/.profile 2>/dev/null
cat /etc/ld.so.preload 2>/dev/null         # should not exist
```

### Package integrity

Check installed files against the package database to spot tampering:

```bash
# Debian/Ubuntu
sudo dpkg --verify
# Fedora, openSUSE
sudo rpm -Va | grep -v '^.......T'
# Arch
sudo pacman -Qkk 2>/dev/null | grep -v ' 0 altered files'
```

Changed configuration files are expected; changed binaries in `/usr/bin` or `/usr/lib` are not.

For continuous file-integrity monitoring (Optional), AIDE is packaged as `aide` on Debian, Ubuntu, Fedora and openSUSE: initialize its database after hardening (`sudo aideinit` on Debian/Ubuntu, `sudo aide --init` elsewhere) and run `sudo aide --check` on a timer.

### Periodic audit

[Lynis](https://cisofy.com/lynis/) is packaged on all five distributions and reports hardening gaps with a score:

```bash
sudo lynis audit system --quick
```

Run it after setup and quarterly; work through its warnings and suggestions.

### Quick monitoring commands

| Command | Task |
| --- | --- |
| `sudo ss -tupn` | Open network connections with process names |
| `journalctl -p warning -b` | Warnings and errors since boot |
| `journalctl _COMM=sudo --since today` | sudo usage today |
| `last -n 20` | Recent logins and reboots |
| `sudo ausearch -m USER_LOGIN -ts today -i` | Login attempts today |
| `ps -eo user,pid,ppid,etime,cmd --sort=-etime \| head -40` | Long-running processes |

## Backups

Back up your work, encrypted, to a location the organization approves, and keep credentials out of the backup. Source code should already live in Git; backups cover local notes, configs and work in progress.

### Tools

| Tool | Type | Encryption | Packaged on |
| --- | --- | --- | --- |
| [restic](https://restic.net/) | CLI, deduplicating | Always (AES-256) | All five |
| [BorgBackup](https://www.borgbackup.org/) | CLI, deduplicating | `repokey` / `keyfile` modes | All five |
| Déjà Dup (GNOME Backups) | GUI, uses restic or duplicity | Optional password; enable it | All five |
| Snapper / Timeshift | Local snapshots | None | Not a backup: same disk |

### Example with restic

```bash
export RESTIC_REPOSITORY=sftp:backup@<host>:/srv/restic/$USER    # or s3:, rest:, a USB drive path
export RESTIC_PASSWORD_COMMAND="secret-tool lookup restic $USER"   # passphrase from the keyring

restic init
restic backup ~ --exclude-file ~/.config/restic/excludes
restic snapshots
restic check
```

`~/.config/restic/excludes`:

```
/home/*/.aws
/home/*/.azure
/home/*/.config/gcloud
/home/*/.kube
/home/*/.ssh/id_*
/home/*/.docker/config.json
/home/*/.cache
/home/*/.local/share/Trash
**/node_modules
**/.terraform
**/*.tfstate*
**/.env
```

Schedule it with a systemd user timer, and store the repository passphrase in your password manager as well as the keyring.

### Rules

- Follow 3-2-1: three copies, two media types, one off-site.
- Never back up to personal cloud storage unless it is an approved, end-to-end encrypted destination.
- Test a restore of a few files every quarter: `restic restore latest --target /tmp/restore-test --include ~/Documents`.
- Wipe backup media that is retired: `cryptsetup erase` for LUKS drives, or physical destruction.

## Incident response and lost devices

Report a lost, stolen or possibly compromised workstation to the security team within 1 hour at `<security-contact>`. Linux workstations usually have no remote wipe, so speed of credential revocation is the main defense; full-disk encryption covers the rest.

### Lost or stolen device

1. Report it immediately, with the asset tag, when and where it was last seen, and whether it was powered off, suspended or unlocked.
2. Security or IT revokes all SSO sessions and refresh tokens for your identity at the IdP.
3. Remove the device's SSH public keys from any `authorized_keys`, Git hosting accounts and the SSH CA trust list; revoke its FIDO2 keys if they were taken with it.
4. Revoke personal access tokens (GitHub/GitLab, registries, API keys) created on that device.
5. If the device was unlocked or suspended without a TPM PIN, treat it as compromised and follow the next list too.
6. File a police report if required by your organization or insurer.

### Suspected compromise

Signs include unexpected MFA prompts, unfamiliar processes reading `~/.aws` or `~/.ssh` in the audit log, new autostart entries, a disabled firewall or EDR agent, or browser extensions you did not install.

1. Disconnect from the network (turn off Wi-Fi, unplug Ethernet), but **leave the machine powered on** so memory evidence survives.
2. Report to the security team from a different device.
3. Do not try to clean the system, delete files or reinstall before the security team says so.
4. From a clean device, sign out of all sessions at the IdP and change your SSO password.
5. Security rotates every secret the workstation could access: cloud roles, Kubernetes credentials, CI/CD variables, database passwords and `.env` contents.
6. After investigation, reinstall from verified media. Do not restore binaries, dotfiles or browser profiles from before the incident without review.

### Retiring a device

- Revoke its SSH keys and tokens as above.
- Destroy the encryption key: `sudo cryptsetup erase /dev/<disk-partition>` removes all LUKS key slots, making the data unrecoverable. Then wipe the disk with the vendor's NVMe secure-erase or `blkdiscard`.
- Remove the device from the asset register.

## Compliance checklist

A workstation must pass every **Required** row before it connects to cloud infrastructure, and again each quarter. Run the command and compare with the expected result.

| # | Control | Level | Verify | Expected |
| --- | --- | --- | --- | --- |
| 1 | Supported OS release | Required | `cat /etc/os-release` | Debian 13, Ubuntu 24.04/26.04 LTS, Fedora 44/45, current Arch, openSUSE Leap 16.0 or Tumbleweed |
| 2 | Secure Boot on | Required | `mokutil --sb-state` | `SecureBoot enabled` |
| 3 | UEFI admin password set | Required | Manual check in firmware setup | Password prompt to enter setup |
| 4 | Firmware current | Required | `fwupdmgr get-updates` | No updates available |
| 5 | Disk encrypted with LUKS2 | Required | `lsblk -o NAME,TYPE,MOUNTPOINTS` | `/` and swap under a `crypt` device |
| 6 | Recovery key escrowed | Required | `sudo cryptsetup luksDump <dev> \| grep -A3 Tokens` | `systemd-recovery` token present; key stored off-device |
| 7 | Automatic security updates | Required | Debian/Ubuntu: `systemctl is-enabled apt-daily-upgrade.timer`; Fedora: `systemctl is-enabled dnf5-automatic.timer`; openSUSE: `systemctl is-enabled os-update.timer`; Arch: `arch-audit` | `enabled`; Arch: no output |
| 8 | Running latest kernel | Required | `uname -r` vs newest installed kernel | Match (reboot within 7 days) |
| 9 | Root password locked | Required | `sudo passwd -S root` | `L` or `LK` |
| 10 | Not in root-equivalent groups | Required | `id -nG` | No `docker`, `lxd`, `incus-admin`, `libvirt`, `disk` |
| 11 | No passwordless sudo | Required | `sudo grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/` | No output |
| 12 | Firewall active, inbound denied | Required | `sudo firewall-cmd --list-all` or `sudo ufw status verbose` or `sudo nft list ruleset` | Default deny incoming; no unexpected services |
| 13 | No unexpected listening services | Required | `sudo ss -tulpn` | Only loopback listeners, or documented exceptions |
| 14 | MAC enforcing | Required (Recommended on Arch) | `getenforce` or `sudo aa-status` | `Enforcing`, or profiles in enforce mode |
| 15 | No static cloud keys on disk | Required | `test -f ~/.aws/credentials && grep -c aws_access_key_id ~/.aws/credentials` | No output or `0` |
| 16 | kubeconfig uses exec plugins | Required | `grep -cE 'token:\|client-key-data:' ~/.kube/config` | `0` |
| 17 | SSH keys protected | Required | `for k in $(ls ~/.ssh/id_* \| grep -v '\.pub$'); do ssh-keygen -y -P '' -f "$k" >/dev/null 2>&1 && echo "UNPROTECTED $k"; done` | No output (or only `-sk` hardware keys) |
| 18 | Credential dirs private | Required | `stat -c '%a %n' ~/.ssh ~/.aws ~/.kube ~/.config/gcloud` | `700` |
| 19 | Screen lock ≤ 5 min | Required | `gsettings get org.gnome.desktop.session idle-delay` | `uint32 300` or less |
| 20 | Browser cookies keyring-encrypted | Required | Desktop session has GNOME Keyring or KWallet | Not using `--password-store=basic` |
| 21 | VPN/ZTNA client installed | Required | Vendor status command | Connected when accessing cloud |
| 22 | EDR / posture agent running | Required if mandated | Vendor status command | Healthy, reporting |
| 23 | Hardening sysctls applied | Recommended | `sysctl kernel.kptr_restrict kernel.unprivileged_bpf_disabled` | `2` and `1` |
| 24 | Core dumps disabled | Recommended | `coredumpctl list` | Empty |
| 25 | auditd running with workstation rules | Recommended | `sudo auditctl -l \| grep -c cloud_creds` | ≥ 4 |
| 26 | Encrypted backup tested this quarter | Recommended | `restic snapshots` | Recent snapshot; restore test logged |
| 27 | Lynis audit run this quarter | Recommended | `sudo lynis audit system --quick` | Warnings reviewed |

Consider wrapping these checks in a script that IT or the EDR agent runs and reports centrally.

## References and further reading

The settings above draw on these benchmarks and distribution guides; consult them for deeper or audited baselines.

### Benchmarks and baselines

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) for Debian, Ubuntu, Red Hat-family, SUSE and distribution-independent Linux
- [ANSSI: Configuration recommendations of a GNU/Linux system](https://cyber.gouv.fr/en/publications/configuration-recommendations-gnulinux-system)
- [Kernel Self Protection Project recommended settings](https://kspp.github.io/Recommended_Settings)
- [DISA STIGs](https://public.cyber.mil/stigs/) for Ubuntu, RHEL and SLES

### Distribution security documentation

- [Debian Security Manual](https://www.debian.org/doc/manuals/securing-debian-manual/) and [Debian security tracker](https://security-tracker.debian.org/)
- [Ubuntu security documentation](https://documentation.ubuntu.com/security/) and [What's new in security for Ubuntu 26.04 LTS](https://canonical.com/blog/ubuntu-26-04-lts-security-updates)
- [Fedora Security and SELinux documentation](https://docs.fedoraproject.org/en-US/quick-docs/selinux-getting-started/)
- [ArchWiki: Security](https://wiki.archlinux.org/title/Security), [dm-crypt](https://wiki.archlinux.org/title/Dm-crypt), [Unified Extensible Firmware Interface/Secure Boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot)
- [openSUSE Security Guide](https://doc.opensuse.org/documentation/leap/security/html/book-security/) and [openSUSE SELinux portal](https://en.opensuse.org/Portal:SELinux)

### Tools referenced

- [fwupd / LVFS](https://fwupd.org/), [sbctl](https://github.com/Foxboron/sbctl), [systemd-cryptenroll(1)](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html)
- [USBGuard](https://usbguard.github.io/), [OpenSnitch](https://github.com/evilsocket/opensnitch), [apparmor.d](https://github.com/roddhjav/apparmor.d)
- [Lynis](https://cisofy.com/lynis/), [restic](https://restic.net/), [BorgBackup](https://www.borgbackup.org/)

### Related guides

- [drduh/macOS-Security-and-Privacy-Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide), the model for this document
- [drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide) for hardware-backed SSH and GPG keys
- [drduh/config](https://github.com/drduh/config) for example `ssh_config` and shell settings

### Release notes used for version information

- [Fedora 45 release](https://phoronix.com/news/Fedora-45-Released) (3 November 2026)
- [openSUSE Leap 16 firewalld defaults](https://computingforgeeks.com/configure-firewalld-opensuse-leap/)
