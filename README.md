# linux-security-guide

Practical security and privacy hardening guides for Linux, covering both ends of a cloud connection: the **servers** you run and the **workstations** you reach them from.

Each guide is modeled on [drduh/macOS-Security-and-Privacy-Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide). Every section starts from a threat model, gives the commands to apply a control, and shows how to check that it worked. Each guide ends with a checklist you can audit against.

## Guides

| Guide | Scope | Platforms | Start here if… |
| --- | --- | --- | --- |
| [**OCI Linux Server Security and Privacy Guide**](server-guide.md) | Linux compute instances on Oracle Cloud Infrastructure: the OCI control plane (tenancy, IAM, network, instance settings) and the guest OS | Oracle Linux 9/10, with notes for Ubuntu 22.04/24.04 | you run anything from a single Always Free VM to a small production fleet |
| [**Linux Workstation Security and Privacy Guide**](workstation-guide.md) | Engineer laptops and desktops that hold SSO sessions, SSH keys and kubeconfigs for cloud infrastructure | Debian 13, Ubuntu 24.04/26.04 LTS, Fedora 44/45, Arch Linux, openSUSE Leap 16.0/Tumbleweed | you use a Linux machine to reach cloud infrastructure |

The two guides complement each other. The workstation guide does not cover servers or cloud resources, and the server guide assumes the admin's endpoint is already trustworthy.

## What's covered

### Server guide ([server-guide.md](server-guide.md))

- **Threat model**: from internet scanners and botnets to insiders, supply-chain attacks and nation-state actors, with mitigations for each
- **OCI tenancy and IAM**: compartments, MFA, dynamic groups instead of user API keys, Cloud Guard, Security Zones
- **Launching instances**: shielded and confidential instances, IMDSv2-only metadata, customer-managed encryption keys
- **Network and remote access**: private subnets, NSGs, OCI Bastion, hardened `sshd`, serial console, and an extended section on [Tailscale](https://tailscale.com/) (tailnet policy, Tailscale SSH vs OpenSSH, sharing, logging)
- **Host hardening**: accounts and sudo, `firewalld`/`nftables` (including restricting metadata access by user), automatic patching with Ksplice/Livepatch, sysctl and kernel module hardening, SELinux/AppArmor, filesystem options, secrets management, containers
- **Detection and response**: auditd, AIDE, OCI Logging and Audit, incident-ready log access with prepared queries, privacy, immutable backups, incident response
- **Checklist** split into per-tenancy and per-server items, plus Lynis and OpenSCAP (CIS profile) commands to automate the audit

### Workstation guide ([workstation-guide.md](workstation-guide.md))

- **Threat model**: thieves, infostealers, supply-chain attackers, phishing, hostile networks and evil-maid attacks
- **Hardware and boot**: UEFI settings, Secure Boot per distribution, firmware updates with fwupd, verified installer images
- **Disk encryption**: LUKS2, recovery key escrow, optional TPM2 or FIDO2 unlock
- **OS hardening**: per-distro update policy, users and sudo, hardware security keys, firewall (firewalld, ufw, nftables), services, USB/Thunderbolt control, sysctl, kernel lockdown, MAC
- **Cloud credential hygiene**: AWS, Google Cloud, Azure, Kubernetes, SSH and Git, with the goal of keeping long-lived secrets off disk
- **Network and applications**: VPN/ZTNA, Wi-Fi, MAC and hostname privacy, encrypted DNS, browser hardening, sandboxed apps, developer tooling
- **Physical security and privacy**: screen lock per desktop environment, telemetry and crash reports
- **Logging, backups and incident response**: auditd rules for credential files, persistence locations to review, restic backups, lost-device and compromise procedures
- **27-point compliance checklist**: each control has a verification command, an expected result and a level (**Required**, **Recommended** or **Optional**)

## How to use these guides

1. **Start with the threat model.** Decide what you're protecting and from whom, then pick the controls worth their cost.
2. **Work through the checklist.** In the server guide, finish the tenancy-wide items first because they protect every server at once. In the workstation guide, a machine must pass every **Required** control before it connects to cloud infrastructure.
3. **Verify, then re-audit.** Run the verification commands after each change, and repeat the audit on a schedule (quarterly for workstations).

> [!WARNING]
> These guides are provided "as is", without warranty. Test every change on a non-production instance or a non-critical machine first. Several settings, including the IMDS version, firewall, SSH, SELinux and disk encryption, can lock you out.

## Further reading

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks), including the [CIS Oracle Cloud Infrastructure Foundations Benchmark](https://www.cisecurity.org/benchmark/oracle_cloud)
- [ANSSI GNU/Linux configuration recommendations](https://cyber.gouv.fr/en/publications/configuration-recommendations-gnulinux-system) and [KSPP recommended settings](https://kspp.github.io/Recommended_Settings)
- [drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide) for hardware-backed SSH and GPG keys
- [drduh/config](https://github.com/drduh/config) for example `sshd`, `ssh_config` and shell settings

Each guide ends with a full list of sources and tools.

## Contributing

Corrections and improvements are welcome. Open an issue or pull request, and when adding a control, include:

- the threat it addresses
- commands for each supported distribution family
- a command that verifies the control is in place
