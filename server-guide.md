# OCI Linux Server Security and Privacy Guide

Nov 12, 2026 · @Ujjwal Upadhyay

This guide collects techniques for securing Linux compute instances on Oracle Cloud Infrastructure (OCI) and limiting what they reveal about you and your users. It covers two layers: the OCI control plane (tenancy, IAM, network, instance settings) and the operating system itself (SSH, firewall, kernel, MAC, logging).

Examples target **Oracle Linux 9/10** (RHEL-compatible, `dnf`, `firewalld`, SELinux) with notes for **Ubuntu 22.04/24.04** (`apt`, `ufw`/`nftables`, AppArmor). Most host-level advice applies to any Linux server; the OCI-specific parts are marked with the service name.

It is written for administrators running anything from a single Always Free VM to a small production fleet. Organizations with compliance requirements should also apply the [CIS Oracle Cloud Infrastructure Foundations Benchmark](https://www.cisecurity.org/benchmark/oracle_cloud) and the CIS benchmark for their distribution.

This guide is provided "as is", without warranty. Test every change on a non-production instance first; several settings (IMDS version, firewall, SSH, SELinux) can lock you out.

**Contents:** Basics · Threat model · Tenancy and IAM · Image and shape · Launching the instance · Network design · Remote access · Tailscale · Accounts and sudo · Host firewall · Updates and patching · Services · Kernel and sysctl · Mandatory access control · Filesystem and data · Secrets · Containers · Logging and detection · Incident-ready log access · Privacy · Backup and recovery · Incident response · Checklist · Resources

## Basics

Apply general security practice before anything OCI-specific:

- **Know the shared responsibility split.** Oracle secures the physical hosts, hypervisor and service APIs. You own IAM, network rules, the guest OS, patches, applications and data.
- **Write a threat model** (next section). Decide what you are protecting and from whom before adding controls.
- **Keep everything patched.** OS packages, kernel, container images and application dependencies. Automate it.
- **Minimize exposure.** No public IP unless the server must serve the internet. No open port without a reason.
- **Least privilege everywhere.** IAM policies, Linux users, sudo rules, service accounts and API keys.
- **Encrypt data** at rest and in transit, with keys you control for sensitive workloads.
- **Log centrally and look at the logs.** Logs that only live on the instance disappear with an attacker.
- **Back up and test restores.** Assume an instance can be lost or encrypted by ransomware.
- **Treat servers as cattle.** Rebuild from code (Terraform, cloud-init, Ansible) instead of hand-editing. A rebuilt server is a known-good server.

## Threat model

The most useful step is deciding what you protect, from whom, and which controls are worth their cost. Stop adding controls when the remaining risk is acceptable, and revisit the model when the workload changes.

**Assets** — list them in order of value: customer data and databases, credentials (SSH keys, API signing keys, auth tokens, Vault secrets), the tenancy itself (an attacker with admin IAM can do anything), compute capacity (crypto-mining), your domain and IP reputation (spam, phishing hosting), and logs/backups.

**Adversaries and capabilities** — rank from least to most capable. Most cloud servers are hit by automated scanners within minutes of getting a public IP; few face a targeted attacker.

| Adversary | Motivation | Capabilities | Mitigations |
| --- | --- | --- | --- |
| Internet scanners and botnets | Crypto-mining, botnet growth, spam relays | Mass port scans, SSH password brute force, known CVE exploits | No public IP, Bastion, key-only SSH, host firewall, automatic patching |
| Opportunistic criminal | Ransom, data theft, resale of access | Leaked credentials, phishing, exploiting web apps, SSRF to metadata | MFA, IMDSv2 only, WAF, least-privilege IAM, immutable backups |
| Malicious or careless insider | Sabotage, data exfiltration, mistakes | Legitimate console/API access | Compartments, separation of duties, Audit logs, Security Zones, break-glass accounts |
| Supply chain | Wide-scale compromise | Malicious packages, poisoned container images, compromised CI | Signed repos only, image scanning, pinned versions, minimal software |
| Cloud provider or legal process | Lawful access, operational access | Access to underlying infrastructure and stored data | Customer-managed keys, region choice, confidential computing, client-side encryption |
| Nation state / APT | Espionage | Zero-days, long dwell time, credential theft | All of the above plus egress allow-listing, file integrity monitoring, detection engineering, short-lived credentials |

Read more: [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling).

## Tenancy and IAM

Whoever controls your tenancy controls every server in it, so IAM is the first thing to harden. A hardened OS does not help if an attacker can detach its boot volume or run commands through the Cloud Agent.

**Compartments.** Split resources by environment and function (for example `Network`, `Security`, `Prod`, `Dev`). Policies and Security Zones attach to compartments, so this is your main blast-radius control.

**Users and MFA.**

- Enable MFA for every console user, and require it for the Administrators group. Prefer FIDO2/passkeys in your identity domain over TOTP.
- Do not use the tenancy administrator for daily work. Keep one or two break-glass admin accounts with hardware keys, stored offline, and alert on their use.
- Federate with your existing IdP (Entra ID, Okta, Google) so leavers lose access in one place.
- Remove unused users, API keys, auth tokens and customer secret keys. Rotate the ones you keep at least every 90 days.

**Least-privilege policies.** Grant groups the narrowest verb (`inspect` < `read` < `use` < `manage`) on the narrowest resource family and compartment:

```
Allow group NetworkAdmins to manage virtual-network-family in compartment Network
Allow group AppOps to use instance-family in compartment Prod
Allow group AppOps to read instance-agent-command-family in compartment Prod
Allow group SecurityAdmins to manage cloud-guard-family in tenancy
```

Avoid `manage all-resources in tenancy` outside the Administrators group. Be careful with `manage instance-agent-command-family`: Run Command executes scripts as root on instances, which is equivalent to a root shell.

**Workload identity.** Do not put user API keys on servers. Put instances in a **dynamic group** and grant the group exactly what the workload needs ("instance principals"):

```
# Dynamic group matching rule
ALL {instance.compartment.id = 'ocid1.compartment.oc1..aaaa...'}

# Policy
Allow dynamic-group app-servers to read secret-bundles in compartment Prod
Allow dynamic-group app-servers to manage objects in compartment Prod where target.bucket.name = 'app-uploads'
```

Any process on the instance that can reach the metadata service can use these credentials, which is one more reason to enforce IMDSv2 and keep dynamic-group policies narrow.

## Choosing an image and shape

Use a current Oracle-provided platform image and pick shielded or confidential features at launch, because both can only be set when the instance is created.

**Image.**

- **Oracle Linux 9 or 10** ships with SELinux enforcing, `firewalld` enabled, the Unbreakable Enterprise Kernel, and access to the OCI regional yum mirrors and Ksplice. **Oracle Autonomous Linux** adds fully automatic daily patching.
- **Ubuntu 22.04/24.04** platform images are also maintained by Oracle and receive Canonical security updates.
- Avoid unknown Marketplace or community images for sensitive workloads. If you build custom images, build them with Packer from a platform image and rebuild regularly.
- Prefer the newest supported major release: older releases lose security fixes first.

**Shielded instances** add [Secure Boot, Measured Boot and a (v)TPM](https://docs.oracle.com/iaas/Content/Compute/References/shielded-instances.htm) at no charge. On VMs you can enable Secure Boot alone, TPM with Measured Boot, or all three; enable all three for the strongest protection. On Linux, Measured Boot is only available on VM instances. Limits to plan around: no custom images, no confidential computing on the same instance, and no live migration.

Secure Boot rejects unsigned kernel modules. If you need third-party drivers (some monitoring or EDR agents), check they are signed before enabling it.

**Confidential computing** encrypts guest memory so the host cannot read it. On the current E5 and E6 shapes, [OCI uses AMD SEV with Secure Nested Paging](https://blogs.oracle.com/cloud-infrastructure/?p=18798) with keys held in the AMD Secure Processor. Supported images include Oracle Linux 9 and 10 with UEK8 and Ubuntu 24.04. It must be enabled at launch, cannot be toggled later, and costs nothing extra. Use it when your threat model includes the provider or a compromised hypervisor.

**Shape.** Flexible shapes (`VM.Standard.E5.Flex`, `VM.Standard.A1.Flex` on Ampere Arm) let you size precisely. Bare metal gives single-tenant hardware if you need to avoid co-tenancy entirely.

## Launching the instance

Set the security-relevant options at launch: several cannot be changed afterwards without rebuilding.

**Instance Metadata Service v2 only.** IMDSv1 at `169.254.169.254/opc/v1/` answers any local HTTP request, so a server-side request forgery (SSRF) bug in a web app can leak instance-principal credentials. IMDSv2 requires an `Authorization: Bearer Oracle` header and rejects requests carrying `Forwarded`/`X-Forwarded-*` headers. The default is still "Versions 1 and 2", so set it explicitly ([docs](https://docs.oracle.com/iaas/Content/Compute/Tasks/updatinginstancemetada.htm)):

```
oci compute instance update --instance-id "$INSTANCE_OCID" \
  --instance-options '{"areLegacyImdsEndpointsDisabled": true}'

# verify from the instance: v2 works, v1 is refused
curl -s -H 'Authorization: Bearer Oracle' http://169.254.169.254/opc/v2/instance/ | head
curl -s -o /dev/null -w '%{http_code}\n' http://169.254.169.254/opc/v1/instance/
```

For defense in depth, block metadata access from non-root users that never need it (see Host firewall).

**Encryption.** [Boot and block volumes are always encrypted at rest](https://docs.oracle.com/iaas/Content/Block/Concepts/blockvolumeencryption.htm) with Oracle-managed keys. For sensitive data, assign a customer-managed key (CMK) from OCI Vault so you control rotation, see every use in Audit, and can disable the key to make data unreadable. Also enable **in-transit encryption** for paravirtualized attachments so traffic between the instance and its volumes is encrypted; it is available on VMs launched from platform images.

```
oci bv boot-volume update --boot-volume-id "$BV_OCID" --kms-key-id "$KEY_OCID"
```

**No public IP.** Put servers in a private subnet and launch with `--assign-public-ip false`. Reach them through Bastion; serve them through a load balancer.

**cloud-init / user data.** User data is readable by anything that can query the metadata service and is stored with the instance. Never put passwords, keys or tokens in it; fetch secrets from Vault at boot instead.

Example launch (verify flags with `oci compute instance launch --help` for your CLI version):

```
oci compute instance launch \
  --compartment-id "$COMPARTMENT" --availability-domain "$AD" \
  --shape VM.Standard.E5.Flex --shape-config '{"ocpus":2,"memoryInGBs":16}' \
  --image-id "$OL9_IMAGE" --subnet-id "$PRIVATE_SUBNET" \
  --assign-public-ip false \
  --nsg-ids '["'"$APP_NSG"'"]' \
  --instance-options '{"areLegacyImdsEndpointsDisabled": true}' \
  --platform-config '{"type":"AMD_VM","isSecureBootEnabled":true,"isMeasuredBootEnabled":true,"isTrustedPlatformModuleEnabled":true}' \
  --is-pv-encryption-in-transit-enabled true \
  --ssh-authorized-keys-file ~/.ssh/oci_ed25519.pub \
  --user-data-file cloud-init.yaml
```

## Network design

The network is your first firewall: a server with no route from the internet cannot be scanned from it.

**Layout.**

- One VCN per environment. **Private subnets** for servers and databases; a small public subnet only for load balancers.
- **Service gateway** for Oracle services (Object Storage, the regional yum mirrors, Vault, Logging), so patching and backups never leave Oracle's network.
- **NAT gateway** only if servers truly need outbound internet access. No internet gateway route on private subnets.
- Enable **VCN flow logs** on every subnet; they are your only record of who talked to what.

**Fix the defaults.** The default security list that the VCN wizard creates allows SSH from `0.0.0.0/0`. The CIS OCI benchmark requires that [no security list or NSG allows 0.0.0.0/0 to port 22 or 3389](https://github.com/turbot/steampipe-mod-oci-compliance/blob/v0.12/cis_v120/section_2.sp), and that the default security list allow only ICMP. Remove that rule first.

**Prefer NSGs over security lists.** Network Security Groups attach to individual VNICs and can reference other NSGs as source or destination, so rules describe roles rather than IP ranges:

| NSG | Ingress | Egress |
| --- | --- | --- |
| `lb-nsg` | TCP 443 from `0.0.0.0/0` | TCP 8080 to `app-nsg` |
| `app-nsg` | TCP 8080 from `lb-nsg`; TCP 22 from the Bastion private endpoint IP | TCP 5432 to `db-nsg`; TCP 443 to Oracle Services Network |
| `db-nsg` | TCP 5432 from `app-nsg` | none |

**Restrict egress.** Default egress rules allow everything, which is how malware phones home and data leaves. Allow only the destinations each role needs. For FQDN-based egress filtering and IDS/IPS, put the **OCI Network Firewall** in the path; for public web apps, put the **OCI WAF** in front of the load balancer.

**IPv6.** If you enable IPv6 on a VCN, mirror every IPv4 rule for `::/0`. Unfiltered IPv6 is a common oversight.

## Remote access

Reach servers through the OCI Bastion service instead of exposing SSH or running your own jump host.

### OCI Bastion

[OCI Bastion](https://blogs.oracle.com/cloud-infrastructure/simplify-secure-access-with-oci-bastion-service) is a managed, IAM-controlled entry point into a private subnet. Sessions are time-limited and closed automatically when their time-to-live expires, and connections are only accepted from client IP ranges on the bastion's allow-list. It is included with every tenancy, including Always Free.

- **Managed SSH session**: the bastion pushes your key to the target. Requires the **Bastion plugin** of Oracle Cloud Agent, which is [disabled by default](https://www.ateam-oracle.com/managed-ssh-session-vs-ssh-port-forwarding-session).
- **Port forwarding session**: an SSH tunnel to any port on a private IP (SSH, a database, an admin UI). No agent needed.

Setup: create the bastion in the target VCN with a tight client CIDR allow-list and a short maximum TTL; allow ingress to the targets only from the bastion's private endpoint IP; grant `use bastion-session` only to the operators who need it.

```
oci bastion session create-managed-ssh \
  --bastion-id "$BASTION" --target-resource-id "$INSTANCE" \
  --target-os-username opc --session-ttl 3600 \
  --ssh-public-key-file ~/.ssh/oci_ed25519.pub

ssh -i ~/.ssh/oci_ed25519 \
  -o ProxyCommand="ssh -i ~/.ssh/oci_ed25519 -W %h:%p -p 22 $SESSION_OCID@host.bastion.$REGION.oci.oraclecloud.com" \
  opc@10.0.1.10
```

Self-managed alternatives: WireGuard on a hardened gateway, or a mesh VPN. Both need their own patching and key management.

### SSH server

Use keys only, no root login, and a short allow-list of users. Put overrides in a drop-in that sorts first (OpenSSH uses the first value it reads):

```
# /etc/ssh/sshd_config.d/00-hardening.conf
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
AllowGroups sshusers
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
MaxAuthTries 3
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
```

Validate and reload **while keeping your current session open**: `sudo sshd -t && sudo systemctl reload sshd` (`ssh` on Ubuntu). Then test a second login before disconnecting.

On Oracle Linux, ciphers come from the system crypto policy. Check it with `update-crypto-policies --show`; `DEFAULT` is reasonable, `FUTURE` is stricter but can break older clients. Audit any host with [ssh-audit](https://github.com/jtesta/ssh-audit).

### Keys

- Generate Ed25519 keys with a passphrase: `ssh-keygen -t ed25519 -a 100 -f ~/.ssh/oci_ed25519`.
- Better: hardware-backed keys (`ssh-keygen -t ed25519-sk -O verify-required`) on a YubiKey, added to `authorized_keys` after first boot.
- One key per person, never shared. Remove keys when people leave; manage `authorized_keys` with configuration management.
- Verify host keys on first connect. Publish them via cloud-init output or SSHFP records rather than trusting on first use.

### Serial console

OCI console connections give out-of-band serial access for recovery. Create one only when needed and delete it afterwards. Logging in over serial needs a local password, so set one only for a break-glass account.

## Tailscale

With Tailscale, servers need no inbound ports at all: admins reach them over a WireGuard mesh, and access is decided by your identity provider and the tailnet policy file. That moves trust to the Tailscale admin console, so protect it as carefully as the OCI console.

This section complements the OpenSSH and Bastion advice above. Keep Bastion (or the serial console) configured as a break-glass path for when the tailnet, your IdP or a node's Tailscale client is unavailable.

### Network rules on OCI

Tailscale only needs outbound connectivity. A server in a private subnet with a NAT gateway works with no ingress rule. Per [Tailscale's firewall guidance](https://tailscale.com/kb/1082/firewall), allow egress to:

| Destination | Purpose |
| --- | --- |
| TCP 443 to `0.0.0.0/0` | coordination server and DERP relays |
| TCP 80 to `0.0.0.0/0` | preferred control-plane transport and captive-portal checks (optional) |
| UDP 3478 to `0.0.0.0/0` | STUN, to discover the public address |
| UDP from port 41641 to `0.0.0.0/0` | direct WireGuard peer-to-peer traffic |

Tailscale advises against narrowing these to IP lists because its relay set changes over time. Run `tailscale status`: `direct` means peer-to-peer, `relay` means traffic goes through a DERP server. Relayed traffic is still end-to-end encrypted, just slower. Only if you need direct connections to an instance with a public IP, also allow ingress UDP 41641.

### Install and join

Install from Tailscale's signed package repository rather than piping a script to a shell, and enable automatic client updates:

```
# Oracle Linux 9 (RHEL-compatible repo); Ubuntu: see pkgs.tailscale.com
sudo dnf config-manager --add-repo https://pkgs.tailscale.com/stable/rhel/9/tailscale.repo
sudo dnf install -y tailscale
sudo systemctl enable --now tailscaled
```

Join servers with an [auth key](https://tailscale.com/kb/1085/auth-keys) that is **tagged** (the server gets a role identity, not a person's), **one-off** (or **ephemeral** for autoscaled nodes), **pre-approved** if device approval is on, and short-lived. Keep the key in OCI Vault, never in cloud-init user data:

```
TS_KEY=$(oci secrets secret-bundle get --auth instance_principal --secret-id "$TS_KEY_SECRET" \
  --query 'data."secret-bundle-content".content' --raw-output | base64 -d)
sudo tailscale up --auth-key="$TS_KEY" --advertise-tags=tag:oci-prod \
  --hostname=app-prod-01 --ssh --accept-dns=false
unset TS_KEY
sudo tailscale set --auto-update
```

`--accept-dns=false` keeps the VCN resolver in charge, so OCI service and private-endpoint names keep resolving; use split DNS if you want MagicDNS names on servers. Reusable keys are dangerous if stolen; for Terraform or CI, mint keys from an OAuth client instead of storing a long-lived one.

Tagged devices have node-key expiry **disabled by default**. That keeps servers online, but it also means a forgotten server stays in the tailnet indefinitely. Remove nodes when you terminate instances (ephemeral keys do this automatically).

### Tailscale SSH or OpenSSH over the tailnet

You can let Tailscale handle SSH itself, or keep the hardened OpenSSH from the Remote access section and use Tailscale only as the network path.

|  | Tailscale SSH (`--ssh`) | OpenSSH over the tailnet |
| --- | --- | --- |
| Authentication | Tailnet identity from your IdP; no `authorized_keys` | SSH keys (ideally hardware-backed), plus tailnet identity to reach the port |
| Authorization | `ssh` rules in the tailnet policy, incl. allowed local users | Tailnet policy for port 22, then `AllowGroups` and keys on the host |
| Re-authentication | **Check mode**: fresh IdP login before the session, repeated after `checkPeriod` | Only what your keys require (for example touch on a FIDO key) |
| Key management | None | Distribute and revoke keys yourself |
| `sshd_config` hardening | Does not apply to these sessions; `tailscaled` (root) is the SSH server | Applies in full |
| Failure mode | IdP or tailnet outage blocks access | Keys still work over Bastion if the tailnet is down |

A sound default: **Tailscale SSH in check mode for people**, keep OpenSSH hardened and reachable only through Bastion for break-glass, and use tightly scoped tagged identities without check mode only for automation. If you prefer two independent factors (IdP + SSH key), use OpenSSH over the tailnet and drop `--ssh`.

Either way, host controls still apply: sudo logging, auditd, SELinux and named local accounts.

**Restrict OpenSSH to the tailnet interface** if you use it that way:

```
sudo firewall-cmd --permanent --new-zone=tailnet
sudo firewall-cmd --permanent --zone=tailnet --add-interface=tailscale0
sudo firewall-cmd --permanent --zone=tailnet --add-service=ssh
sudo firewall-cmd --reload
```

`tailscaled` installs its own netfilter rules, so treat the tailnet policy as the primary filter for tailnet traffic and verify the host rules by testing from another node (`nc -vz app-prod-01 5432` should fail if the port is not granted).

### Tailnet policy

Replace the default allow-all rule with explicit grants. Grants are Tailscale's newer syntax, and plain ACLs [will not receive new features](https://tailscale.com/docs/reference/examples/acls). Example:

```
{
  "groups": {
    "group:sre": ["alice@example.com", "bob@example.com"],
    "group:dev": ["carol@example.com"]
  },
  "tagOwners": {
    "tag:oci-prod": ["group:sre"],
    "tag:oci-dev":  ["group:sre"]
  },
  "grants": [
    {"src": ["group:sre"], "dst": ["tag:oci-prod", "tag:oci-dev"], "ip": ["tcp:22", "tcp:443"]},
    {"src": ["group:dev"], "dst": ["tag:oci-dev"], "ip": ["tcp:22", "tcp:8080"]},
    {"src": ["tag:oci-prod"], "dst": ["tag:oci-prod"], "ip": ["tcp:5432"]}
  ],
  "ssh": [
    {"action": "check", "checkPeriod": "4h",
     "src": ["group:sre"], "dst": ["tag:oci-prod"], "users": ["autogroup:nonroot"]},
    {"action": "check", "checkPeriod": "12h",
     "src": ["group:dev"], "dst": ["tag:oci-dev"], "users": ["autogroup:nonroot"]}
  ],
  "tests": [
    {"src": "carol@example.com", "deny": ["tag:oci-prod:22"]}
  ]
}
```

- Log in as a named non-root user and escalate with sudo, so sudo logs show who did what. Avoid `root` in `users`.
- `tagOwners` decides who can put a server into a role: keep it to a small admin group.
- `tests` run on every policy save and block changes that would open prod to the wrong people.
- Keep the policy file in Git and apply it through the API or the Terraform provider, with review.

### Harden the tailnet

- **SSO with phishing-resistant MFA** for every user, enforced at your IdP. Keep Owner and Admin roles to a few people.
- **Device approval** so new user devices need an admin's approval; use pre-approved keys only for infrastructure.
- **Tailnet Lock** so new nodes must be signed by trusted signing nodes you hold. This protects you even if the coordination server were compromised. Pre-sign server auth keys with `tailscale lock sign`.
- **Key expiry** on for user devices (180 days by default); only infrastructure should have it disabled.
- **No unneeded roles on servers.** Don't advertise exit nodes or subnet routes from application servers. If you run a subnet router into a VCN, it exposes everything its routes cover, so grant it narrowly. Prefer Tailscale on each server.
- **Keep Funnel off.** Funnel publishes a service to the public internet; do not grant the `funnel` node attribute to server tags unless that is the intent. `tailscale serve` (tailnet-only HTTPS) is fine for internal tools.

### Sharing

[Node sharing](https://tailscale.com/blog/sharing-over-tailscale) gives a user in another tailnet access to one device, without exposing it publicly. The recipient sees only that device, and the share goes from a device to a user, not to their network.

- Limit what shared-in users can reach with a grant from `autogroup:shared` to specific ports, rather than everything on the node.
- Shares cannot be granted to tags, so they suit people, not automation.
- For regular collaborators who need SSH, invite them into the tailnet (as members or guests) so your groups and `ssh` rules apply.
- Review shares and revoke unused ones from the Machines page on a schedule.
- For files, use `scp`/`rsync` over the tailnet to servers. Taildrop is for personal devices.

### Logging and privacy

- On the host: `journalctl -u tailscaled`, `tailscale status`, `tailscale netcheck`. auditd and sudo logs still capture what people do once logged in.
- In the admin console: configuration audit logs record policy, key and device changes. Network flow logs, log streaming to a SIEM and SSH session recording are available on some plans; enable them where you can and send them to the same place as your OCI logs.
- Tailscale cannot read traffic, which is end-to-end WireGuard, but its coordination service sees metadata: users, device names, OS, IPs and, with flow logs, who connected to whom. Name devices by role, not by customer or person.
- The client sends diagnostic logs to Tailscale by default. To opt out on a server, add `--no-logs-no-support` to `FLAGS` in `/etc/default/tailscaled` and restart; you lose Tailscale support's ability to debug that node.
- `tailscale cert` HTTPS certificates are public, so machine names appear in Certificate Transparency logs under your `ts.net` name.
- If your threat model rules out a third-party control plane, [Headscale](https://github.com/juanfont/headscale) is a self-hosted coordination server compatible with the Tailscale clients.

## Accounts and sudo

Give every administrator a named account and keep the default cloud user for emergencies only.

Platform images create `opc` (Oracle Linux) or `ubuntu` with passwordless sudo and your launch key. Anyone holding that key is root, and logs show only "opc".

```
# named admin in the SSH allow-list group
sudo groupadd -f sshusers
sudo useradd -m -G wheel,sshusers alice      # use group 'sudo' on Ubuntu
sudo install -d -m 700 -o alice -g alice /home/alice/.ssh
sudo install -m 600 -o alice -g alice alice.pub /home/alice/.ssh/authorized_keys

# lock root's password
sudo passwd -l root
```

After named accounts work, remove `opc` from `sshusers` (or delete its key) and keep it as break-glass.

**sudo.** Log every command with a pseudo-terminal, and require re-authentication where practical:

```
# /etc/sudoers.d/10-hardening  (edit with: visudo -f /etc/sudoers.d/10-hardening)
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults timestamp_timeout=5
```

Passwordless sudo is common on key-only cloud servers. If you keep it, compensate with hardware-backed SSH keys and central logging of every sudo command. If you set passwords, enforce `pam_pwquality` and lock out repeated failures with `pam_faillock` (`authselect enable-feature with-faillock` on Oracle Linux).

**Service accounts.** Run each application as its own non-login user (`useradd -r -s /usr/sbin/nologin app`). Never run applications as root.

Audit regularly:

```
awk -F: '$3 >= 1000 {print $1, $7}' /etc/passwd      # human accounts and shells
getent group wheel sudo sshusers                       # who can escalate or log in
sudo find /home -name authorized_keys -exec ls -l {} \;
sudo lastlog | grep -v 'Never'
```

## Host firewall

Run a host firewall even behind NSGs: it still protects you if a cloud rule is loosened by mistake, and it can filter by user and process, which NSGs cannot.

> **Do not break the link-local rules.** OCI instances depend on `169.254.0.0/16` for the metadata service, DNS and NTP (`169.254.169.254`) and, on iSCSI-attached volumes, the boot volume (`169.254.0.2:3260`). Oracle's Ubuntu images ship with pre-built `iptables` rules for this in `/etc/iptables/rules.v4`; Oracle advises against replacing them with `ufw`, which can leave an instance unbootable. Edit the existing rules instead.

### firewalld (Oracle Linux)

Allow SSH only from the Bastion subnet and drop everything else that isn't explicitly opened:

```
sudo firewall-cmd --permanent --new-zone=mgmt
sudo firewall-cmd --permanent --zone=mgmt --add-source=10.0.0.0/28   # bastion subnet
sudo firewall-cmd --permanent --zone=mgmt --add-service=ssh
sudo firewall-cmd --permanent --zone=public --remove-service=ssh
sudo firewall-cmd --permanent --zone=public --remove-service=cockpit
sudo firewall-cmd --permanent --zone=public --remove-service=dhcpv6-client
sudo firewall-cmd --permanent --zone=public --add-port=8080/tcp      # your app
sudo firewall-cmd --permanent --set-log-denied=unicast
sudo firewall-cmd --reload
```

| Command | Task |
| --- | --- |
| `firewall-cmd --get-active-zones` | which zones apply to which interfaces/sources |
| `firewall-cmd --list-all --zone=public` | rules in a zone |
| `nft list ruleset` | the full rules actually loaded |
| `journalctl -k -g 'REJECT\|DROP'` | denied packets (with log-denied on) |

### Restrict metadata access by user

Only root, the Cloud Agent and any app that uses instance principals should reach the metadata API. A separate nftables table does this without touching firewalld's rules:

```
# /etc/nftables/imds-guard.nft  (load via a systemd unit or nftables.service include)
table inet imds_guard {
  chain output {
    type filter hook output priority 0; policy accept;
    ip daddr 169.254.169.254 tcp dport 80 meta skuid { root, oracle-cloud-agent } accept
    ip daddr 169.254.169.254 tcp dport 80 log prefix "imds-deny " reject
  }
}
```

Check the agent's user with `ps -o user= -C agent` first, and add your app's user if it needs instance-principal credentials. DNS (53) and NTP (123) to the same address are unaffected.

### Egress

For high-value servers, set outbound policy to deny and allow only what is needed (the Oracle Services Network, your database, your package mirror). Malware that cannot call home is far less useful.

## Updates and patching

Automate security updates, patch the kernel without waiting for reboots where you can, and reboot on a schedule anyway.

**Oracle Linux — dnf-automatic:**

```
sudo dnf install -y dnf-automatic
sudo sed -i -e 's/^upgrade_type.*/upgrade_type = security/' \
            -e 's/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf
sudo systemctl enable --now dnf-automatic.timer
sudo dnf needs-restarting -r      # exit code 1 = reboot required
```

**Ksplice** applies kernel and key user-space fixes (glibc, OpenSSL) to a running system without a reboot. It is [included with an OCI Compute subscription](https://oracle.com/a/ocom/docs/linux/linux-oci-infographic.pdf). Check which client your image has with `rpm -q uptrack ksplice`, then run `sudo uptrack-upgrade -y` or `sudo ksplice -y all upgrade`. Ksplice reduces reboots; it does not replace them, so still reboot into new kernels during maintenance windows.

**OS Management Hub** gives fleet-wide patch reporting and scheduling, lifecycle environments (dev → test → prod) and Ksplice management. It is [included with OCI Compute](https://www.oracle.com/il/linux/os-management/), works through the OS Management Hub plugin of Oracle Cloud Agent, and [needs agent version 1.40 or later](https://docs.oracle.com/iaas/osmh/doc/overview.htm). **Oracle Autonomous Linux** goes further and patches itself daily with no operator action.

**Ubuntu — unattended-upgrades:**

```
sudo apt install -y unattended-upgrades needrestart
sudo dpkg-reconfigure -plow unattended-upgrades
# optional: automatic reboot at a quiet hour
echo 'Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:30";' | \
  sudo tee /etc/apt/apt.conf.d/52auto-reboot
cat /var/run/reboot-required 2>/dev/null
```

Ubuntu Pro adds Livepatch (rebootless kernel fixes) and extended security maintenance.

**Stay informed.** Subscribe to [Oracle Linux errata (ELSA)](https://linux.oracle.com/errata.html) or [Ubuntu Security Notices](https://ubuntu.com/security/notices), and patch applications and containers on the same cadence as the OS.

## Services and attack surface

Every listening service and installed package is something to patch and something to exploit. Remove what the server does not need.

| Command | Task |
| --- | --- |
| `sudo ss -tulpn` | listening sockets and their processes |
| `systemctl list-unit-files --state=enabled` | services and sockets started at boot |
| `systemctl list-timers` | scheduled jobs |
| `sudo systemctl disable --now <unit>` | stop and disable a service |
| `sudo systemctl mask <unit>` | prevent it from ever starting |
| `dnf list --installed` / `apt list --installed` | installed packages |

Common candidates on a headless server, if unused: `cockpit.socket`, `rpcbind`, `avahi-daemon`, `cups`, `bluetooth`, `ModemManager`, `nfs-server`, `postfix` (or bind it to localhost only), `snapd` on Ubuntu. Remove compilers and debugging tools from production images; an attacker who lands a shell will use them.

Bind internal services (databases, caches, admin consoles) to `127.0.0.1` or the private IP, never `0.0.0.0`. Re-run `ss -tulpn` after every deployment and compare it with what you expect.

Oracle Cloud Agent plugins are services too. Enable only the ones you use (see Privacy).

## Kernel and sysctl hardening

A handful of sysctls close common local-privilege-escalation and network-spoofing paths at almost no cost. Test before production: a few break debuggers, containers or routing.

```
# /etc/sysctl.d/90-hardening.conf   — apply with: sudo sysctl --system
# kernel information and attack surface
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.yama.ptrace_scope = 2          # 1 if you need gdb/strace as non-root
kernel.kexec_load_disabled = 1
kernel.sysrq = 0
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# network (not a router)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
```

Leave `net.ipv4.ip_forward` and `user.max_user_namespaces` alone on container hosts: Podman and Docker need them.

**Unused kernel modules.** Prevent loading of filesystems and protocols a cloud server never uses:

```
# /etc/modprobe.d/90-disable.conf
install cramfs /bin/false
install freevxfs /bin/false
install hfs /bin/false
install hfsplus /bin/false
install jffs2 /bin/false
install udf /bin/false
install usb-storage /bin/false
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install bluetooth /bin/false
```

**Boot parameters** (optional, small performance cost): memory zeroing and allocator hardening.

```
sudo grubby --update-kernel=ALL --args="init_on_alloc=1 init_on_free=1 slab_nomerge page_alloc.shuffle=1 randomize_kstack_offset=on"
# Ubuntu: add to GRUB_CMDLINE_LINUX in /etc/default/grub, then update-grub
```

**Core dumps** can contain secrets. Disable them unless you need them: set `Storage=none` in `/etc/systemd/coredump.conf` and `* hard core 0` in `/etc/security/limits.d/`.

## Mandatory access control

Keep SELinux (Oracle Linux) or AppArmor (Ubuntu) enforcing. It confines services so that a compromised web server cannot read `/etc/shadow` or open arbitrary ports, even as root. Disabling it to "fix" an application is one of the most common hardening regressions.

**SELinux (Oracle Linux):**

| Command | Task |
| --- | --- |
| `getenforce` / `sestatus` | confirm `Enforcing` with the `targeted` policy |
| `sudo ausearch -m avc -ts recent` | recent denials |
| `sudo ausearch -m avc -ts recent \| audit2why` | why a denial happened |
| `sudo semanage port -a -t http_port_t -p tcp 8080` | let a web server use a non-standard port |
| `sudo setsebool -P httpd_can_network_connect_db on` | flip a policy boolean persistently |
| `sudo restorecon -Rv /srv/app` | fix file labels after moving files |

Fix denials with booleans, port labels and file contexts. Write a custom module with `audit2allow` only as a last resort, and review what it allows. Never set `SELINUX=disabled`; use `semanage permissive -a <domain>` to debug a single domain.

**AppArmor (Ubuntu):** check with `sudo aa-status`, put a profile in enforce mode with `sudo aa-enforce /etc/apparmor.d/<profile>`, and find denials with `journalctl -k -g apparmor`. Install `apparmor-profiles` for extra profiles, and write profiles for your own services.

**systemd sandboxing** adds per-service confinement on either distro. For your own units:

```
[Service]
User=app
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
CapabilityBoundingSet=
ReadWritePaths=/var/lib/app
```

Score any unit with `systemd-analyze security <unit>`.

## Filesystem and data

Restrict where code can execute and who can read data, and add your own encryption layer for data that must stay unreadable even to the provider.

**Mount options.** Make temporary and shared-memory filesystems non-executable:

```
# /etc/fstab
tmpfs  /dev/shm  tmpfs  defaults,nodev,nosuid,noexec  0 0
tmpfs  /tmp      tmpfs  defaults,nodev,nosuid,noexec,size=1G  0 0
# data block volumes
UUID=...  /srv/data  xfs  defaults,_netdev,nofail,nodev,nosuid  0 2
```

Use `_netdev,nofail` for iSCSI-attached volumes so a missing volume doesn't stop the boot. Some installers unpack into `/tmp`; point them at another `TMPDIR` rather than dropping `noexec`.

**Permissions.**

- Set `UMASK 027` in `/etc/login.defs` so new files are not world-readable.
- Find world-writable files: `sudo find / -xdev -type f -perm -0002 -ls`
- Review SUID/SGID binaries: `sudo find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -ls`
- Find files without an owner: `sudo find / -xdev -nouser -o -nogroup`

**Your own encryption layer.** OCI already encrypts volumes at rest. Add LUKS on data volumes when you want the key to live only with you, so a copied volume or backup is useless without it. On a shielded instance, Clevis can unlock automatically with the vTPM:

```
sudo cryptsetup luksFormat --type luks2 /dev/oracleoci/oraclevdb
sudo dnf install -y clevis clevis-luks clevis-systemd
sudo clevis luks bind -d /dev/oracleoci/oraclevdb tpm2 '{"pcr_ids":"7"}'
```

Binding to PCR 7 ties unlocking to the Secure Boot state. Alternatively, fetch the passphrase from OCI Vault at boot with instance-principal credentials. Keep a recovery passphrase offline.

**Data minimization.** The best-protected data is data you never stored. Set retention limits on application logs, uploads and database tables, and delete what you no longer need.

## Secrets management

Keep secrets in OCI Vault and fetch them at runtime with instance-principal credentials. Nothing secret should live in images, user data, Git or shell history.

**OCI Vault** stores master encryption keys (optionally HSM-protected) and secrets with versioning, rotation and audit logging. Use a separate vault per environment, and restrict who can manage keys versus who can use them.

Fetch a secret from the instance without any stored credential:

```
oci secrets secret-bundle get --auth instance_principal \
  --secret-id "$SECRET_OCID" \
  --query 'data."secret-bundle-content".content' --raw-output | base64 -d
```

Scope the dynamic-group policy to named secrets where possible (`where target.secret.name = 'db-password'`).

**Handling on the host.**

- Deliver secrets to services with systemd credentials (`LoadCredential=` / `SetCredentialEncrypted=`) or files mode `0400` owned by the service user, not environment variables visible in `/proc/<pid>/environ` to the same user.
- Keep `HISTCONTROL=ignorespace` and prefix commands containing secrets with a space; better, never type secrets on the command line.
- Rotate secrets on a schedule and immediately when someone with access leaves.
- Scan repositories and images for leaked keys (for example with [gitleaks](https://github.com/gitleaks/gitleaks) or [trufflehog](https://github.com/trufflesecurity/trufflehog)).

If an OCI API key or auth token leaks, delete it in IAM first, then investigate in Audit what it was used for.

## Containers

If the server runs containers, the container runtime becomes part of your attack surface. Prefer rootless Podman, minimal images you can trace to a source, and tight runtime flags.

- **Rootless by default.** Oracle Linux ships Podman; run containers as an unprivileged user so a container escape lands as that user, not root. Never mount `/var/run/docker.sock` into a container: it grants root on the host.
- **Trusted images.** Pull from OCI Container Registry (OCIR) or official sources, pin by digest (`image@sha256:...`), and rebuild regularly. OCI Vulnerability Scanning can scan OCIR images; OCIR also supports signing images with Vault keys.
- **Tight runtime flags:**

```
podman run -d --name app \
  --read-only --tmpfs /tmp \
  --cap-drop=ALL --security-opt no-new-privileges \
  --userns=keep-id --pids-limit 256 --memory 512m \
  -v /srv/app/data:/data:Z \
  -p 127.0.0.1:8080:8080 \
  registry.example.com/app@sha256:<digest>
```

- `:Z` relabels the volume for SELinux so the container can use it and nothing else can. Never disable SELinux separation with `--security-opt label=disable` in production.
- Publish ports on `127.0.0.1` or the private IP, not on all interfaces. Docker in particular inserts its own firewall rules that bypass `firewalld`/`ufw` for published ports.
- Run containers as systemd services (Quadlet `.container` files) so they restart cleanly and log to the journal.

## Logging, monitoring and detection

Record security events on the host, ship them off it, and turn on OCI's detection services, most of which cost nothing.

### On the host

**auditd** records who changed what. A starting rule set:

```
# /etc/audit/rules.d/50-hardening.rules   — load with: sudo augenrules --load
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /root/.ssh/ -p wa -k ssh_keys
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k root_cmd
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
-e 2
```

`-e 2` makes the rules immutable until reboot, so an intruder cannot quietly turn auditing off. Query with `sudo ausearch -k identity -i` and summarize with `sudo aureport --summary`.

**journald**: make it persistent (`Storage=persistent` in `/etc/systemd/journald.conf`) and cap its size.

**File integrity**: AIDE detects changed binaries and configs.

```
sudo dnf install -y aide        # or: apt install aide
sudo aide --init && sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
sudo aide --check               # run daily from a systemd timer
```

**Ship logs off the host.** The Custom Logs Monitoring plugin of Oracle Cloud Agent sends files and the journal to OCI Logging; or forward to your own SIEM. Logs that stay on a compromised host can be erased.

### In OCI

| Service | What it does | Cost |
| --- | --- | --- |
| [Audit](https://docs.cloud.oracle.com/Content/Audit/Tasks/settingretentionperiod.htm) | Records every API call to the tenancy; always on. Retained 365 days, fixed. | Included |
| Logging + Connector Hub | Central service/custom logs (VCN flow logs, Bastion, load balancer, agent logs); Connector Hub copies logs and Audit to Object Storage for long-term retention or to a SIEM. | Usage-based |
| Cloud Guard | Detects risky configuration (open security lists, public buckets, disabled MFA) and suspicious activity; can auto-remediate. | Included with paid tenancies |
| [Security Zones](https://docs.oracle.com/en-us/iaas/Content/cloud-adoption-framework/security-strategy.htm) | Prevents policy-violating resources from being created in a compartment (for example public subnets or unencrypted volumes). Requires Cloud Guard. | Included |
| [Vulnerability Scanning](https://docs.oracle.com/iaas/scanning/using/overview.htm) | Scans hosts and container images for CVEs, open ports and CIS benchmark gaps; results appear in Cloud Guard. Needs the Vulnerability Scanning agent plugin. | Included |
| [Cloud Guard Instance Security](https://docs.oracle.com/iaas/cloud-guard/using/cgis.htm) | eBPF-based runtime detection with MITRE ATT&CK–aligned rules and osquery for threat hunting. A free recipe covers 5 instances per region with limited rules; the Enterprise recipe is paid. | Free tier / paid |

Wire alerts to people: create **Events** rules for IAM policy changes, security list/NSG changes, new API keys and Cloud Guard problems, and send them to a **Notifications** topic (email, Slack, PagerDuty).

**fail2ban** still helps for internet-facing apps (web logins, mail). For SSH behind Bastion it adds little.

## Incident-ready log access

The goal: within five minutes of an alert, any responder can search every log for a given host, user or IP across the last 90 days, from one console. That must hold even when the affected server or an admin account is compromised. Three things make it possible: every log ships to one place in near real time, a locked copy exists that nobody can delete, and access and queries are prepared before anything happens.

&#91;embedded content: incident log pipeline · 3 sources, 2 destinations\]

Responders start in Logging Analytics or the SIEM; the locked bucket is the fallback and the evidence of record.

### What to collect

| Source | Answers | Route | Searchable | Archive |
| --- | --- | --- | --- | --- |
| OCI Audit (`_Audit`) | Who changed IAM, network, instances, keys, and from which IP | Always on | 365 days, fixed | Connector Hub → locked bucket |
| VCN flow logs | Which addresses talked, on which ports, accepted or rejected | Service log per subnet | Up to 180 days | Connector Hub → locked bucket |
| Bastion, load balancer, WAF, Object Storage read/write | Who connected, what was requested, which objects were read | Service logs | Up to 180 days | Connector Hub → locked bucket |
| Host: `/var/log/secure` (`auth.log`), `/var/log/messages` (`syslog`), `/var/log/audit/audit.log`, `/var/log/sudo.log`, app logs | Logins, sudo commands, process and file changes, app errors | Custom Logs Monitoring plugin → custom log | Up to 180 days | Connector Hub → locked bucket |
| `tailscaled` on each host | Tailnet connections and Tailscale SSH sessions | journald → rsyslog file → custom log | Up to 180 days | as above |
| Tailscale configuration audit and network flow logs | Policy, key and device changes; tailnet traffic metadata | [Tailscale log streaming](https://tailscale.com/kb/1255/log-streaming) to an S3-compatible bucket (OCI Object Storage) | In your SIEM or Logging Analytics | Locked bucket |
| Cloud Guard, Vulnerability Scanning | Detected problems and vulnerable hosts | Cloud Guard → Events → Notifications | Cloud Guard console | Optional |

Tailscale log streaming depends on your plan: configuration logs stream on more plans than network flow logs. Check the log streaming page for yours.

**Host agent setup.** Create one custom log per environment and an agent configuration that targets a dynamic group of instances, listing the file paths above. Oracle Linux and Ubuntu Server already copy journald into those files through rsyslog, so `tailscaled`, `sshd` and `sudo` messages are included. Enable the Custom Logs Monitoring plugin on every instance.

### One place to search

- **OCI Logging Search** (included): one query across compartments and log groups, including `_Audit`. Good for fast first looks, but it searches a limited time window per query.
- **OCI Logging Analytics**: Connector Hub feeds it every log above. It parses Linux, audit and Audit-service formats into fields, and adds saved searches, dashboards and [detection rules](https://docs.oracle.com/en-us/iaas/logging-analytics/doc/manage-detection-rules.html) that raise Monitoring alarms. Use it, or your own SIEM fed through Connector Hub, as the single console responders open first.
- **The locked archive bucket** is the source of truth if anything else has gaps or was tampered with.

### Prepared queries

Save these in advance as saved searches (Logging Search syntax, per the [query language spec](https://docs.oracle.com/iaas/Content/Logging/Reference/query_language_specification.htm)) and pin them to an "Incident" dashboard. Replace the placeholders.

```
-- 1. Everything mentioning a host or IP, newest first
search "<tenancy_ocid>"
  | where logContent = '*app-prod-01*' or logContent = '*10.0.1.23*'
  | sort by datetime desc

-- 2. Every cloud API call by one person
search "<tenancy_ocid>/_Audit"
  | where data.identity.principalName = 'alice@example.com'
  | sort by datetime desc

-- 3. IAM changes (event names follow the API operation names)
search "<tenancy_ocid>/_Audit"
  | where data.eventName = 'CreatePolicy' or data.eventName = 'UpdatePolicy'
     or data.eventName = 'UploadApiKey' or data.eventName = 'CreateAuthToken'
     or data.eventName = 'CreateUser' or data.eventName = 'AddUserToGroup'
  | sort by datetime desc

-- 4. Logins and sudo commands on hosts
search "<security_logs_compartment_ocid>/host-logs"
  | where logContent = '*sshd*Accepted*' or logContent = '*sudo*COMMAND=*'
     or logContent = '*tailscaled*ssh*'
  | sort by datetime desc

-- 5. All traffic to or from a suspicious address
search "<network_compartment_ocid>/vcn-flowlogs"
  | where data.sourceAddress = '203.0.113.7' or data.destinationAddress = '203.0.113.7'
  | sort by datetime desc
```

The same queries run from a terminal, which helps when the console is slow or you want the results in a file:

```
oci logging-search search-logs \
  --search-query "search \"$TENANCY/_Audit\" | where data.identity.principalName = 'alice@example.com'" \
  --time-start 2026-11-10T00:00:00Z --time-end 2026-11-12T23:59:59Z > alice-audit.json

# pull archived logs for a period
oci os object bulk-download --bucket-name security-log-archive \
  --prefix 2026/11/ --download-dir ./ir-logs
```

### Access when it matters

Grant read access to responders before an incident, not during one:

```
Allow group IncidentResponders to read log-groups in tenancy
Allow group IncidentResponders to read log-content in tenancy
Allow group IncidentResponders to read audit-events in tenancy
Allow group IncidentResponders to read objects in compartment SecurityLogs
Allow group IncidentResponders to use loganalytics-features-family in tenancy
```

Check the Logging Analytics policy names against Oracle's IAM documentation for your setup.

- Keep log groups, connectors and the archive bucket in a dedicated `SecurityLogs` compartment that production admins cannot manage. An attacker who takes a prod admin account should not be able to delete the evidence.
- Make sure at least one responder can sign in if your identity provider or federation is down: use the break-glass accounts from Tenancy and IAM.
- Keep the runbook (this section, the saved-search links, the dashboard URL) somewhere reachable without the tenancy, such as your incident channel.

### Make the logs trustworthy

- **Immutable archive.** The archive bucket has versioning and a locked retention rule (for example 400 days, to outlast Audit's 365). Connector Hub can write; nobody can delete.
- **Alert on silence.** A compromised host can stop its agent. Create a detection rule or alarm that fires when a host sends no logs for 15 minutes, and alarm on Connector Hub errors: the Logging source keeps only 24 hours of backlog, so a connector broken longer than that loses data.
- **Synchronized time.** Correlation across sources fails without it. Keep chrony pointed at the OCI time source (`169.254.169.254`, the image default), check with `chronyc tracking`, and read all logs in UTC.
- **Tamper-resistant host logs.** auditd rules locked with `-e 2` (Logging, monitoring and detection) and persistent journald, so even local evidence survives until it is shipped.

### Practice

Run a 15-minute drill every month: pick a random host and a random user, answer "what happened on it, and what did they do in the last 24 hours" with the saved searches, and time it. Fix whatever was missing or slow. Once a quarter, restore a day of logs from the archive bucket to prove it works.

## Privacy

A cloud server leaks information about you and your users through agents, metadata, DNS, certificates and logs. Decide what you are willing to share with the provider and the internet.

**Oracle Cloud Agent plugins.** The agent can monitor metrics, ship logs, apply patches, scan for vulnerabilities, run commands and broker Bastion sessions. Each plugin is a channel between the instance and Oracle's control plane. Enable only those you use, and review them in the instance's **Oracle Cloud Agent** tab:

```
oci compute instance update --instance-id "$INSTANCE" --agent-config '{
  "pluginsConfig": [
    {"name": "Compute Instance Run Command", "desiredState": "DISABLED"},
    {"name": "Bastion", "desiredState": "ENABLED"},
    {"name": "Vulnerability Scanning", "desiredState": "ENABLED"}
  ]}'
```

**Run Command** executes scripts as root from the console or API. Disable it unless you use it, and restrict `instance-agent-command-family` in IAM.

**Metadata and names.** Display names, tags and descriptions are visible to anyone with read access to the compartment and to processes on the instance through the metadata service. Do not put customer names, emails or other personal data in them.

**DNS.** By default the instance resolves through the VCN resolver at `169.254.169.254`, which Oracle operates; keep it for OCI service and private-endpoint names. For other lookups you can run a local resolver (for example Unbound) that forwards over DNS-over-TLS to a resolver you trust.

**TLS certificates.** Public certificates are logged in Certificate Transparency, which exposes every hostname you issue one for. Use a wildcard certificate if internal hostnames are sensitive, and use OCI Certificates or a private CA for internal services.

**Distribution telemetry (Ubuntu).** Disable news and reporting you don't need:

```
sudo sed -i 's/^ENABLED=.*/ENABLED=0/' /etc/default/motd-news
sudo apt purge -y popularity-contest ubuntu-report 2>/dev/null
```

**Data location and provider access.** Data stays in the region you choose unless you copy it (cross-region backups, replication). Oracle, like any provider, is subject to legal process in the jurisdictions where it operates. Customer-managed keys, confidential computing and your own LUKS/application-level encryption limit what can be read at rest or in memory.

**Your users' data.** Web, mail and application logs hold IP addresses and identifiers. Log only what you need, truncate or hash IPs where possible, and set retention limits on log groups and buckets.

## Backup and recovery

Assume an attacker with admin access will try to delete your backups. Make at least one copy immutable, encrypted, and outside the reach of the credentials that run production.

- **Volume backups.** Attach a backup policy to boot and block volumes, and use volume groups for crash-consistent multi-volume backups. Copy backups to a second region for disaster recovery.
- **Immutable volume backups.** Block Storage now offers [Retention Lock for boot and block volume backups](https://blogs.oracle.com/cloud-infrastructure/oci-block-storage-adds-ransomware-backup): a locked backup cannot be deleted before expiry, its period can be extended but not shortened, and the lock itself is irreversible. Choose the retention period and key strategy before locking.
- **File-level backups to Object Storage.** Use a dedicated bucket with versioning and a locked retention rule (WORM). Once the rule is locked, nobody can delete objects before the period ends. Encrypt client-side first, for example with [restic](https://restic.net/) against Object Storage's S3-compatible endpoint:

```
export AWS_ACCESS_KEY_ID=...  AWS_SECRET_ACCESS_KEY=...   # customer secret key, write-only bucket policy
export RESTIC_REPOSITORY="s3:https://$NAMESPACE.compat.objectstorage.$REGION.oraclecloud.com/backups"
export RESTIC_PASSWORD_FILE=/root/.restic-pass
restic init
restic backup /srv /etc --exclude-caches
restic check --read-data-subset=5%
```

- **Separate the blast radius.** Keep backups in their own compartment. The identity that writes backups should not be able to delete them, and production admins should not administer backup retention.
- **Infrastructure as code is a backup.** Terraform/OCI Resource Manager and cloud-init let you rebuild a clean server in minutes; store that code outside the tenancy too.
- **Test restores** on a schedule (for example quarterly): restore a volume backup to a new instance and confirm the application starts. An untested backup is a hope, not a backup.

## Incident response

If you suspect a compromise: contain the instance, preserve evidence, cut its credentials, then rebuild from a known-good source. Do not "clean" a compromised server in place.

1. **Contain the network.** Remove the instance from load balancers and swap its NSGs for an empty quarantine NSG. Security list rules still apply in addition to NSGs, which is another reason to keep subnet security lists minimal.

   ```
   oci network vnic update --vnic-id "$VNIC" --nsg-ids '["'"$QUARANTINE_NSG"'"]' --force
   ```
2. **Cut cloud credentials.** Remove the instance from its dynamic group (for example by changing the tag the matching rule uses) so stolen instance-principal tokens stop working, and rotate any Vault secrets it could read.
3. **Capture volatile evidence** before shutdown if you can: memory with a tool such as [AVML](https://github.com/microsoft/avml) or LiME, plus `ps`, `ss -tupan` and `last` output, written to attached storage, not the suspect disk.
4. **Preserve disks.** Clone or back up the boot and block volumes into a forensics compartment, then stop the instance.

   ```
   oci bv boot-volume create --source-boot-volume-id "$BOOT_VOL" \
     --compartment-id "$FORENSICS" --availability-domain "$AD" --display-name ir-$(date +%F)
   ```
5. **Investigate on a copy.** Attach the clone read-only to an analysis instance in an isolated VCN. Correlate with Audit, VCN flow logs, Cloud Guard problems and shipped host logs.
6. **Check the tenancy, not just the host.** Look in Audit for new users, API keys, policies, auth tokens, instances or images created around the incident.
7. **Recover.** Rebuild from code and a fresh image, restore data from a backup older than the intrusion, rotate every secret and SSH key the host touched.
8. **Learn.** Write down the root cause and which control would have prevented or detected it sooner, then add it.

## Hardening checklist

Tick these off per tenancy and per server. The first group protects every server at once, so do it first.

**Tenancy**

- [ ] MFA on every console user; hardware keys for admins; break-glass accounts stored offline
- [ ] Compartments per environment; no `manage all-resources` outside Administrators
- [ ] No user API keys on servers; workloads use dynamic groups with narrow policies
- [ ] Default security lists allow ICMP only; no 0.0.0.0/0 to port 22 or 3389 anywhere
- [ ] Cloud Guard enabled, Security Zones on production compartments, Vulnerability Scanning on all hosts
- [ ] Events + Notifications for IAM, network and Cloud Guard changes
- [ ] Audit and key logs copied to Object Storage via Connector Hub

**Each server**

- [ ] Current platform image; shielded (Secure Boot, Measured Boot, vTPM) or confidential instance
- [ ] Private subnet, no public IP, access through Bastion only
- [ ] IMDSv2 only (`areLegacyImdsEndpointsDisabled: true`)
- [ ] Customer-managed key and in-transit encryption on boot and block volumes
- [ ] NSGs with least-privilege ingress and egress
- [ ] SSH: keys only, no root, `AllowGroups`, validated with ssh-audit
- [ ] Named admin accounts; default `opc`/`ubuntu` key retired; sudo logging
- [ ] Host firewall on; link-local OCI rules intact; metadata limited by user
- [ ] Automatic security updates; Ksplice or Livepatch; scheduled reboots
- [ ] Unused services and Cloud Agent plugins disabled; Run Command off unless needed
- [ ] Sysctl and module hardening applied; core dumps off
- [ ] SELinux/AppArmor enforcing
- [ ] Secrets from Vault, none in user data, images or Git
- [ ] auditd rules, AIDE, logs shipped off-host
- [ ] Backups with an immutable copy; restore tested

Automate the audit: `sudo lynis audit system` gives a quick score, and OpenSCAP checks against the CIS profile:

```
sudo dnf install -y openscap-scanner scap-security-guide
sudo oscap xccdf eval --profile cis_server_l1 \
  --report /tmp/cis-report.html /usr/share/xml/scap/ssg/content/ssg-ol9-ds.xml
```

## Related software and resources

**Benchmarks and guides**

- [CIS Oracle Cloud Infrastructure Foundations Benchmark](https://www.cisecurity.org/benchmark/oracle_cloud) and CIS benchmarks for Oracle Linux and Ubuntu
- [OCI Best Practices: Manage your operating systems](https://docs.oracle.com/en/solutions/oci-best-practices/manage-your-operating-systems1.html)
- [Oracle Linux security guides](https://docs.oracle.com/en/operating-systems/oracle-linux/) and [Ubuntu security documentation](https://ubuntu.com/security)
- [drduh/macOS-Security-and-Privacy-Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide), the model for this guide, and [drduh/config](https://github.com/drduh/config) for sshd and ssh client configs

**Tools**

- [Lynis](https://cisofy.com/lynis/) — host security audit
- [OpenSCAP / SCAP Security Guide](https://www.open-scap.org/) — automated CIS/STIG checks and remediation
- [ssh-audit](https://github.com/jtesta/ssh-audit) — SSH server and client configuration audit
- [AIDE](https://aide.github.io/) — file integrity monitoring
- [restic](https://restic.net/) — encrypted, deduplicated backups
- [gitleaks](https://github.com/gitleaks/gitleaks) — secret scanning
- [Steampipe/Powerpipe OCI compliance mod](https://hub.powerpipe.io/mods/turbot/oci_compliance) — CIS OCI checks across a tenancy

**Sources**

- [Updating the Instance Metadata Service (Oracle)](https://docs.oracle.com/iaas/Content/Compute/Tasks/updatinginstancemetada.htm) and [CIS OCI 2.0 control 3.1 (Powerpipe)](https://hub.powerpipe.io/mods/turbot/oci_compliance/controls/control.cis_v200_3_1)
- [Shielded Instances (Oracle)](https://docs.oracle.com/iaas/Content/Compute/References/shielded-instances.htm)
- [OCI Confidential Computing with AMD SEV-SNP (Oracle blog)](https://blogs.oracle.com/cloud-infrastructure/?p=18798)
- [Block Volume Encryption (Oracle)](https://docs.oracle.com/iaas/Content/Block/Concepts/blockvolumeencryption.htm)
- [CIS OCI section 2 network controls (Steampipe)](https://github.com/turbot/steampipe-mod-oci-compliance/blob/v0.12/cis_v120/section_2.sp)
- [Simplify secure access with OCI Bastion (Oracle blog)](https://blogs.oracle.com/cloud-infrastructure/simplify-secure-access-with-oci-bastion-service) and [Managed SSH vs port forwarding sessions (Oracle A-Team)](https://www.ateam-oracle.com/managed-ssh-session-vs-ssh-port-forwarding-session)
- [Oracle Linux on OCI infographic](https://oracle.com/a/ocom/docs/linux/linux-oci-infographic.pdf), [OS Management Hub overview](https://docs.oracle.com/iaas/osmh/doc/overview.htm), [OS Management Hub product page](https://www.oracle.com/il/linux/os-management/)
- [Audit log retention period (Oracle)](https://docs.cloud.oracle.com/Content/Audit/Tasks/settingretentionperiod.htm)
- [Enable security operations: Cloud Guard, Security Zones, VSS (Oracle CAF)](https://docs.oracle.com/en-us/iaas/Content/cloud-adoption-framework/security-strategy.htm) and [Vulnerability Scanning overview](https://docs.oracle.com/iaas/scanning/using/overview.htm)
- [Cloud Guard Instance Security (Oracle)](https://docs.oracle.com/iaas/cloud-guard/using/cgis.htm)
- [OCI Block Storage adds immutable backups (Oracle blog)](https://blogs.oracle.com/cloud-infrastructure/oci-block-storage-adds-ransomware-backup)
