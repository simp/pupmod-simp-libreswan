# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## What this module does

`simp-libreswan` is a SIMP Puppet module that installs **Libreswan** (the
IPsec/VPN implementation) on Enterprise Linux and, **only when explicitly asked
to**, manages its configuration. As of 5.0.0 the module is safe-by-default: a
bare `include libreswan` installs the libreswan package and declares *nothing
else* — no `/etc/ipsec.conf` changes, no policy files, no service, no
firewall, no PKI/NSS, no haveged. Every behavior beyond package install is
opt-in via class parameters. The `libreswan::connection` defined type remains
the public API for defining individual IPsec tunnels.

### Business logic

The main class orchestrates a set of contained sub-classes behind opt-in
guards; the public API for *tunnels* is the `libreswan::connection` define.

- **`libreswan` (`manifests/init.pp`)** — Public entry class. Three parameters
  are **required** and come from module data: `$service_name`, `$package_name`
  (`data/os/RedHat.yaml`), and `$nssdir` (`data/common.yaml`, EL8 override in
  `data/os/RedHat-8.yaml`). It:
  - Always contains `libreswan::install` → `libreswan::config`.
  - Contains `libreswan::service` (and wires `config ~> service`) **only when
    `$service_ensure` or `$service_enable` is non-`undef`** — the
    `=~ NotUndef` guard appears before every `~> Class['libreswan::service']`
    edge in the module (`init.pp`, `connection.pp`).
  - When `$firewall` (Boolean, default `false`), contains
    `libreswan::config::firewall`; when `$pki` (`false`/`true`/`'simp'`,
    default `false`), contains `libreswan::config::pki` ~>
    `libreswan::config::pki::nsspki`; when `$haveged` (default `false`),
    includes `haveged`; when `$nss_scripts` (default `false`), includes
    `libreswan::nss`.
  - Sets the NSS `$token` based on FIPS: `'NSS FIPS 140-2 Certificate DB'`
    when `$fips or $facts['fips_enabled']`, else `'NSS Certificate DB'`.
    This token must match everywhere NSS is manipulated.
  - Computes `$nsspassword = "${ipsecdir}/nsspassword"` — pluto reads the
    password file from the **config** dir even when the DB lives in `$nssdir`.
  - Most `ipsec.conf` field parameters (`protostack`, `plutodebug`, `dumpdir`,
    `virtual_private`, the five `*_cidrs`, etc.) are `Optional[...] = undef`,
    meaning "not managed."

- **`libreswan::install` (private, `install.pp`)** — installs `$package_name`.
  Nothing else (the NSS helper script moved to `libreswan::nss`).

- **`libreswan::service` (private, `service.pp`)** — declares the service
  **only if** `$service_ensure`/`$service_enable` is non-`undef`, splatting
  just the non-`undef` attributes onto the resource.

- **`libreswan::config` (private, `config.pp`)** — does NOT render
  `/etc/ipsec.conf`. It builds a `$_settings` hash mapping ipsec.conf keys to
  class parameters and declares one `libreswan::config::setting` per
  **non-`undef`** entry, editing `/etc/ipsec.conf` in place with `file_line`
  (the `config setup` header is expected from the package-provided file).
  Policy files under `${ipsecdir}/policies/` are written only when their
  `$*_cidrs` parameter is set. `$purge_settings`/`$purge_policies` remove
  fields/files; a key appearing in both the managed set and a purge list is a
  compile-time `fail()`. The `ipsecdir`/`nssdir` operational paths are
  deliberately **not** in `$_settings`.

- **`libreswan::config::setting` (define, `config/setting.pp`)** — one
  `key = value` line in an ipsec.conf-style file; `ensure => absent` (with an
  explicit `key`, title prefixed `purge-`) removes it. The `match` regex
  escapes `.` and `-` in keys.

- **`libreswan::config::firewall` (private, `config/firewall.pp`)** — opens
  IKE (500), NAT-T (4500), ESP, and AH; only reached when
  `libreswan::firewall => true`. It selects the backend from
  `simplib::lookup('iptables::use_firewalld', { 'default_value' => true })`:
  `simp_firewalld::rule` when firewalld, else `iptables::listen::udp` /
  `iptables::rule`.

- **`libreswan::config::pki` / `libreswan::config::pki::nsspki`
  (`config/pki.pp`, `config/pki/nsspki.pp`)** — only reached when
  `libreswan::pki` is `true` or `'simp'` (`'simp'` additionally includes
  `simp/pki`). `config::pki` copies certs into
  `/etc/pki/simp_apps/libreswan/x509` via `pki::copy`; `nsspki` initializes
  the NSS DB **in `$nssdir`** and loads the certs (via the `nss::*` defines),
  and writes the cert name into `$secretsfile` (`/etc/ipsec.secrets`).

- **`libreswan::nss` (`nss.pp`)** — installs the
  `/usr/local/scripts/nss/update_nssdb_password.sh` helper. Pulled in
  automatically by `libreswan::nss::init_db`, or directly via
  `libreswan::nss_scripts => true`.

- **`libreswan::connection` (public define, `connection.pp`)** — the primary
  API: renders one `${dir}/${name}.conf` (default dir `/etc/ipsec.d`) from
  `connection.conf.erb`. It notifies the service **only when the service is
  managed** (same `NotUndef` guard). Endpoints `$left`/`$right` are
  `Libreswan::ConnAddr`; crypto defaults `$ike`/`$phase2alg` are `'aes-sha2'`.
  The special title **`'default'`** renders as `conn %default`.

- **`libreswan::nss::{init_db,loadcacerts,loadcerts}` (internal defines)** —
  the NSS plumbing: initialise the DB (and set FIPS mode via `modutil`), load
  CA certs (`certutil`), and load the server cert/key (`pk12util`).

### The `simp:defaults` compliance profile

`SIMP/compliance_profiles/` ships a **`simp:defaults`** profile
(`profile-simp_defaults.yaml` + `checks.yaml`, one `puppet-class-parameter`
check per value) that restores the pre-refactor (4.0.0) behavior wholesale:
service running+enabled, the previously-hardcoded `ipsec.conf` fields, the
five policy files, `firewall=true`, `pki='simp'`, `haveged=true`,
`nss_scripts=true`. Sites activate it by installing the
`simp-compliance_engine` gem and setting
`compliance_engine::enforcement: [simp:defaults]` in Hiera. Profile values
land at middle Hiera priority, so explicit site Hiera still wins.
`spec/classes/simp_defaults_profile_spec.rb` guards this restore path;
`.fixtures.yml` pulls `simp-compliance_engine` for it.

When repairing tests (unit or acceptance) written against the old
auto-manage behavior, **opt in via test hieradata using exactly the knobs the
profile flips — never re-widen the module's defaults.**

### Gotchas / non-obvious details

- **The `simp_options::*` class-default seam is gone from `init.pp`.** Hiera
  keys like `simp_options::firewall`, `simp_options::pki`,
  `simp_options::haveged` no longer influence this module — set
  `libreswan::firewall`, `libreswan::pki`, `libreswan::haveged`, etc.
  directly (or use the `simp:defaults` profile). Only three `simplib::lookup`
  calls remain: `simp_options::pki::source` (`config/pki.pp`),
  `simp_options::fips` (`nss/init_db.pp`), and the module-local
  `iptables::use_firewalld` (`config/firewall.pp`).
- **Firewall backend is chosen by `iptables::use_firewalld`, not
  `simp_options::firewall`** — and whether the firewall is managed at all is
  solely the `libreswan::firewall` parameter.
- **`libreswan::nss::init_db::init_command` has no default** and the define
  fails if it is unset (`nss/init_db.pp`). It is OS-specific and supplied
  from module data (`data/os/*.yaml`).
- **The NSS token name must line up everywhere.** It is derived once in
  `init.pp` and reused by every `certutil`/`pk12util`/`modutil` call; a
  mismatch makes cert loading fail.
- **`$nssdir` vs `$ipsecdir`.** The NSS DB lives in `$nssdir`
  (`/var/lib/ipsec/nss` by default; `/etc/ipsec.d` on EL8) while the password
  file stays in `$ipsecdir` — don't assume they are the same directory.
  Neither path is emitted to `ipsec.conf`; the module data matches each OS's
  package default, so the in-file values are left alone.
- **`ddos_ike_treshold` is intentionally misspelled** to match a Libreswan
  3.1.5 source typo (`init.pp`) — do not "fix" it.
- **`simp/simp_options` is NOT a declared dependency** in `metadata.json`;
  it is a test fixture only.

## Dependencies

Module dependencies (from `metadata.json`):

- `simp/simplib` `>= 4.9.0 < 6.0.0` (provides `simplib::lookup`,
  `simplib::assert_metadata`, `simplib::passgen`, and the `Simplib::*` types)
- `puppetlabs/stdlib` `>= 8.0.0 < 10.0.0` (`file_line`)
- `simp/iptables` `>= 6.5.3 < 9.0.0` (iptables firewall backend +
  `iptables::use_firewalld`)
- `simp/simp_firewalld` `>= 0.1.3 < 3.0.0` (the firewalld backend)
- `simp/pki` `>= 6.2.0 < 8.0.0` (`pki::copy`; used only when `$pki`)
- `simp/haveged` `>= 0.4.5 < 1.0.0` (entropy daemon; included only when
  `$haveged`)

`simp-compliance_engine` (the Ruby gem) is deliberately **not** a
`metadata.json` dependency — it is the activation mechanism for the
`simp:defaults` profile, installed by sites that want it.

Fixture-only dependencies (from `.fixtures.yml`, for test compilation only):
`simp_options`, `augeas_core`, `firewalld`, `systemd`, and
`simp-compliance_engine`.

Runtime requirement (from `metadata.json` `requirements`): `openvox
>= 8.0.0 < 9.0.0`.

Supported OS matrix (from `metadata.json`): CentOS 9/10; RedHat 8/9/10;
OracleLinux 8/9/10; Rocky 8/9/10; AlmaLinux 8/9/10.

## Repository layout

- `manifests/init.pp` — the `libreswan` class (opt-in orchestration + all
  `config setup` field parameters, most `Optional = undef`).
- `manifests/install.pp`, `manifests/service.pp`, `manifests/config.pp` —
  private install/service/config classes (see Business logic).
- `manifests/config/setting.pp` — the `file_line` wrapper define for single
  ipsec.conf fields.
- `manifests/config/firewall.pp` — private; firewalld-vs-iptables rules.
- `manifests/config/pki.pp`, `manifests/config/pki/nsspki.pp` — PKI cert copy
  + NSS load.
- `manifests/nss.pp` — NSS helper-script install (opt-in / pulled by
  `nss::init_db`).
- `manifests/connection.pp` — the public `libreswan::connection` define
  (tunnel API).
- `manifests/nss/{init_db,loadcacerts,loadcerts}.pp` — NSS DB plumbing
  defines.
- `types/` — custom data types: `Libreswan::ConnAddr`,
  `Libreswan::Interfaces`, `Libreswan::VirtualPrivate`, and the
  `Libreswan::Ip::*::Virtualprivate` types.
- `templates/etc/ipsec.d/connection.conf.erb` — each `conn` stanza. This is
  the **only** template left; `ipsec.conf.erb` and the five policy templates
  were removed in 5.0.0.
- `SIMP/compliance_profiles/` — the `simp:defaults` restore profile.
- `data/common.yaml`, `data/os/RedHat.yaml`, `data/os/RedHat-8.yaml` — module
  data (the required `$service_name`/`$package_name`/`$nssdir` and the
  OS-specific `nss::init_db::init_command`); `hiera.yaml` is the v5 hierarchy.
- `metadata.json` — deps, OS matrix, OpenVox requirement.
- `spec/classes/`, `spec/defines/` — rspec-puppet unit tests. The
  `init_spec.rb`/`config_spec.rb`/`install_spec.rb` suites assert that a bare
  include declares **no** service/file/file_line/firewall resources — keep
  those guards intact.
- `spec/acceptance/suites/default/` — beaker acceptance suite (two-host
  left/right IPsec tunnel + clean-state checks); nodesets under
  `spec/acceptance/nodesets/`.
- No `lib/` — the module defines no custom Ruby
  types/providers/functions/facts.
- **Acceptance runs in CI:** `.github/workflows/pr_tests.yml` has an
  `acceptance` job (matrix `almalinux9`, `almalinux10`) whose final step runs
  `bundle exec rake beaker:suites[default,<node>]` under
  `BEAKER_HYPERVISOR=vagrant_libvirt`.

## Common commands

```sh
# Install dependencies
bundle install

# Run all unit tests
bundle exec rake spec

# Run a single spec
bundle exec rspec spec/defines/connection_spec.rb

# Puppet lint
bundle exec rake lint

# Ruby lint
bundle exec rake rubocop

# Regenerate REFERENCE.md from puppet-strings docstrings
puppet strings generate --format markdown --out REFERENCE.md

# Run the default beaker acceptance suite
bundle exec rake beaker:suites[default]
```

Relevant gem pins (from `Gemfile`): `simp-rake-helpers ~> 6.0`,
`simp-rspec-puppet-facts ~> 4.0.0`, `simp-beaker-helpers ~> 3.1`.
`spec/spec_helper.rb` requires `voxpupuli/test/spec_helper` (this module has
moved to the voxpupuli-test harness rather than `puppetlabs_spec_helper`).

## Conventions

- **Preserve the safe-by-default contract.** New behavior must be opt-in
  (`Optional = undef` or a `false` Boolean) and guarded in `init.pp`; add the
  matching restore entry to `SIMP/compliance_profiles/checks.yaml` if it was
  part of the pre-5.0.0 defaults.
- Manage new `ipsec.conf` fields by adding the parameter to `init.pp` and the
  key to the `$_settings` map in `config.pp` — never reintroduce a template
  for `/etc/ipsec.conf`.
- Define tunnels with `libreswan::connection`; use the `'default'` title for
  shared `conn %default` settings.
- Keep OS-specific values (`service_name`, `package_name`, `nssdir`,
  `nss::init_db::init_command`) in `data/`, not hard-coded in manifests.
- Guard the firewall backend on `iptables::use_firewalld` and keep both the
  firewalld and iptables paths in sync when adding a rule
  (`config/firewall.pp`).
- Guard every `~> Class['libreswan::service']` edge with the
  `$service_ensure =~ NotUndef or $service_enable =~ NotUndef` check.
- Preserve the `@summary` / `@param` puppet-strings docstrings — they drive
  `REFERENCE.md`. Regenerate `REFERENCE.md` after changing docs or parameters.
- `Gemfile`, `spec/spec_helper.rb`, and `.github/workflows/pr_tests.yml` carry
  a **puppetsync** notice — they are baseline-managed and the next sync
  overwrites local edits. Push changes to those files upstream to the
  baseline, not here.
- Match the existing 2-space Puppet indentation and aligned-arrow parameter
  style used in `manifests/`.
