# SELinux MLS Module — `aegis-mls`

> **Estado:** PoC / Reference policy for **Fedora / RHEL / CentOS Stream**.
> Debian and Ubuntu do **not** ship the MLS reference policy by default;
> `setup_mls.sh` will refuse on those distros unless you have manually
> rebuilt `selinux-policy` with the `mls` strain. AppArmor remains the
> primary MAC layer on Debian-based images.

This directory ships a minimal Bell–La Padula policy module that elevates the
HispanShield daemons (`aegis-sentinel`, `aegis-gatekeeper`, `llama-server`)
into dedicated SELinux domains and pins their data, log and secret directories
to MLS sensitivity levels.

## Files

| File | Role |
|------|------|
| `aegis-mls.te` | Type-Enforcement + MLS module. Declares `aegis_exec_t`, `aegis_data_t`, `aegis_log_t`, `aegis_secret_t`, the init-domain transition, and the `mlsconstrain` rules implementing No-Read-Up / No-Write-Down. |
| `aegis-mls.fc` | File-context bindings. Maps the binaries under `/opt/hispanshield/...`, the runtime data under `/var/lib/hispanshield`, the audit logs under `/var/log/hispanshield`, and the secrets under `/etc/hispanshield/secrets` and `/run/credentials/aegis-*.service` to the right type and sensitivity (`s1` / `s2`). |
| `setup_mls.sh` | Idempotent installer: pulls the MLS toolchain, compiles the module, applies the file contexts and provisions per-user clearances. |

## Build & install (manual)

```bash
# 1. Compile the textual module to a binary policy module.
checkmodule -M -m -o aegis-mls.mod aegis-mls.te

# 2. Bundle the module with its file contexts into a loadable package.
semodule_package -o aegis-mls.pp -m aegis-mls.mod -f aegis-mls.fc

# 3. Load it.
sudo semodule -i aegis-mls.pp

# 4. Re-label the protected paths so existing files inherit the new contexts.
sudo restorecon -RFv /opt/hispanshield /var/log/hispanshield \
                     /var/lib/hispanshield /etc/hispanshield/secrets

# 5. Verify.
seinfo -t | grep aegis_   # should list aegis_exec_t / aegis_data_t / aegis_secret_t / aegis_log_t
sestatus                   # should report `Policy MLS status: enabled`
```

`setup_mls.sh` performs steps 1–5 plus the toolchain install and per-user
clearance assignment in one go; run it as root on a freshly-provisioned host.

## What is genuinely enforced

- **No-Read-Up** on regular files via `mlsconstrain file { read getattr open } (l1 dom l2)`.
- **Strict No-Write-Down** via `mlsconstrain file { write append } (l1 eq l2)`. Drop the equality clause for relaxed BLP.
- **Secret confinement:** only subjects whose clearance dominates `s2` may even `open` files labelled `aegis_secret_t`.
- **Audit-log immutability** vs every domain except `auditd_t` (`neverallow`).
- **Domain transition** so `init_t` always launches the sentinel under `aegis_exec_t` (no inherited shell privileges).

## Roadmap — what is **not** yet production-grade

- [ ] **Constraint coverage** for `dir`, `lnk_file`, `chr_file`, `unix_stream_socket`, IPC and Netlink classes. The current rules only cover the `file` class; a full BLP policy must extend across every object class the daemons touch.
- [ ] **Range transitions** for `audit2allow`-derived denials — currently there is no `range_transition` block, so a daemon launched at `s2` can fork children that stay at `s2` even when they should drop to `s1` for log emission.
- [ ] **Role separation** between `aegis_admin_r` and `aegis_operator_r`. Today everything runs as `staff_u:staff_r:aegis_exec_t` which is too broad for a real classified deployment.
- [ ] **MCS categories** (compartments) on top of the MLS levels, so cross-mission data cannot be read even at the same clearance.
- [ ] **Common Criteria evidence package** (security target, functional spec, dev environment doc). The module compiles and loads but has not been audited against an EAL profile.
- [ ] **Debian/Ubuntu support** — requires upstream packaging work or a switch to refpolicy with an MLS overlay.

Until those items land, treat this module as a **defence-in-depth research
artefact** layered on top of the AppArmor profiles in `os_base/apparmor/`,
not as a stand-alone classification boundary.
