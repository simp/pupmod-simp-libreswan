# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## What this module does

`simp-libreswan` is a SIMP Puppet module that installs and configures
**Libreswan** (the IPsec/VPN implementation) on Enterprise Linux. It installs
the package, renders the global `/etc/ipsec.conf` `config setup` section and the
opportunistic-policy group files, manages the **NSS certificate database** that
pluto uses for keys, optionally wires in SIMP PKI certificates and the firewall
(IKE/NAT-T/ESP/AH), and exposes the `libreswan::connection` defined type as the
public API for defining individual IPsec tunnels.

### Business logic

The main class orchestrates a set of contained sub-classes; the public API for
*tunnels* is the `libreswan::connection` define.

- **`libreswan` (`manifests/init.pp:147-243`)** — Public entry class. Three
  parameters are **required** and come from module data: `$service_name`,
  `$package_name` (`init.pp:148-149`), and `$nssdir` (`init.pp:190`). It:
  - Sets the NSS `$token` based on FIPS: `'NSS FIPS 140-2 Certificate DB'` when
    `$fips or $facts['fips_enabled']`, else `'NSS Certificate DB'`
    (`init.pp:207-211`). This token must match everywhere NSS is manipulated.
  - `include`s `haveged` (ordered before the service) when `$haveged`
    (`init.pp:213-217`).
  - Computes `$nsspassword = "${ipsecdir}/nsspassword"` — pluto reads the
    password file from the **config** dir even when the DB lives in `$nssdir`
    (`init.pp:219-221`).
  - **`contain`s** `libreswan::install` → `libreswan::config` ~>
    `libreswan::service` (`init.pp:223-228`).
  - When `$firewall`, contains `libreswan::config::firewall`
    (`init.pp:230-234`); when `$pki`, contains `libreswan::config::pki` ~>
    `libreswan::config::pki::nsspki` ~> service (`init.pp:236-242`).

- **`libreswan::install` (private, `install.pp:4`)** — installs `$package_name`,
  creates the `/usr/local/scripts/nss/` password-management scripts and the
  `$ipsecdir` (mode `0700`).

- **`libreswan::service` (private, `service.pp:4`)** — runs/enables
  `$service_name`.

- **`libreswan::config` (private, `config.pp:4`)** — renders `/etc/ipsec.conf`
  from `ipsec.conf.erb` and the five policy-group files (`block`, `clear`,
  `clear-or-private`, `private`, `private-or-clear`) under
  `${ipsecdir}/policies/` (`config.pp:46-93`). The policy files are always
  written but stay empty when their `$*_cidrs` params are unset — harmless.

- **`libreswan::config::firewall` (private, `config/firewall.pp:4`)** — opens
  IKE (500), NAT-T (4500), ESP, and AH. It selects the backend from
  `simplib::lookup('iptables::use_firewalld', { 'default_value' => true })`
  (`config/firewall.pp:6`): `simp_firewalld::rule` when firewalld, else
  `iptables::listen::udp` / `iptables::rule`.

- **`libreswan::config::pki` (internal, no `assert_private`; called only from
  `init`) / `libreswan::config::pki::nsspki` (private,
  `config/pki/nsspki.pp:11`)** — `config::pki` copies SIMP PKI certs into
  `/etc/pki/simp_apps/libreswan/x509` via `pki::copy` using
  `simp_options::pki::source` (`config/pki.pp:21`); `nsspki` loads those certs
  into the NSS DB (calling the `nss::*` defines below) and writes the cert name
  into `$secretsfile` (`/etc/ipsec.secrets`).

- **`libreswan::connection` (public define, `connection.pp`)** — the primary
  API: renders one `${dir}/${name}.conf` (default dir `/etc/ipsec.d`) from
  `connection.conf.erb` and notifies the service. Endpoints `$left`/`$right`
  are `Libreswan::ConnAddr`; crypto defaults `$ike`/`$phase2alg` are
  `'aes-sha2'`. The special title **`'default'`** renders as `conn %default`
  (shared defaults for all tunnels).

- **`libreswan::nss::{init_db,loadcacerts,loadcerts}` (internal defines)** —
  the NSS plumbing: initialise the DB (and set FIPS mode via `modutil`), load CA
  certs (`certutil`), and load the server cert/key (`pk12util`, converting
  PEM→P12 as needed).

### Gotchas / non-obvious details

- **`libreswan::nss::init_db::init_command` has no default** and the define
  fails if it is unset (`nss/init_db.pp:32`). It is OS-specific and supplied
  from module data (`data/os/*.yaml`), so it is not a `simp_options::*` toggle.
- **Firewall backend is chosen by `iptables::use_firewalld`, not
  `simp_options::firewall`** (`config/firewall.pp:6`). `simp_options::firewall`
  only decides *whether* to manage the firewall at all (`init.pp:151`,
  `init.pp:230`).
- **The NSS token name must line up everywhere.** It is derived once in
  `init.pp:207-211` and reused by every `certutil`/`pk12util`/`modutil` call;
  a mismatch makes cert loading fail.
- **`$nssdir` vs `$ipsecdir`.** On EL9+ the NSS DB lives in `/var/lib/ipsec/nss`
  while the password file stays in `$ipsecdir` (`init.pp:219-221`) — don't
  assume they are the same directory.
- **`ddos_ike_treshold` is intentionally misspelled** to match a Libreswan
  3.1.5 source typo (`init.pp:186`) — do not "fix" it.
- **`simp/simp_options` is NOT a declared dependency** in `metadata.json`, yet
  the manifests consume the `simp_options::*` seam via `simplib::lookup`
  (provided by `simp/simplib`); `simp_options` is a test fixture only.

## The `simp_options` / `simplib::lookup` seam

The module's lookup seam (the natural target for a lookup-path unit test):

| Line | Key | `default_value` |
|------|-----|-----------------|
| `init.pp:150` | `simp_options::trusted_nets` | `['127.0.0.1/32']` |
| `init.pp:151` | `simp_options::firewall` | `false` |
| `init.pp:152` | `simp_options::fips` | `false` |
| `init.pp:153` | `simp_options::pki` | `false` |
| `init.pp:154` | `simp_options::haveged` | `false` |
| `config/pki.pp:21` | `simp_options::pki::source` | `/etc/pki/simp/x509` |
| `nss/init_db.pp:29` | `simp_options::fips` | `false` |
| `config/firewall.pp:6` | `iptables::use_firewalld` (module-local, not `simp_options::*`) | `true` |
| `nss/init_db.pp:32` | `libreswan::nss::init_db::init_command` (module-local; **no default**, fails if unset) | — |

Keep routing SIMP feature toggles through `simplib::lookup('simp_options::*', {
'default_value' => ... })` with an explicit default rather than assuming
`simp_options` is included. There are no `assert_optional_dependency` calls;
`haveged` and `pki` are hard `metadata.json` dependencies used conditionally at
runtime.

## Dependencies

Module dependencies (from `metadata.json`):

- `simp/simplib` `>= 4.9.0 < 6.0.0` (provides `simplib::lookup`,
  `simplib::assert_metadata`, `simplib::passgen`, and the `Simplib::*` types)
- `puppetlabs/stdlib` `>= 8.0.0 < 10.0.0`
- `simp/iptables` `>= 6.5.3 < 9.0.0` (the iptables firewall backend +
  `iptables::use_firewalld`)
- `simp/simp_firewalld` `>= 0.1.3 < 3.0.0` (the firewalld backend)
- `simp/pki` `>= 6.2.0 < 8.0.0` (`pki::copy`; used only when `$pki`)
- `simp/haveged` `>= 0.4.5 < 1.0.0` (entropy daemon; included only when
  `$haveged`)

No optional dependencies (`metadata.json` declares no
`simp.optional_dependencies`).

Fixture-only dependencies (from `.fixtures.yml`, for test compilation only):
`augeas_core`, `firewalld`, `systemd`.

Runtime requirement (from `metadata.json` `requirements`): `openvox
>= 8.0.0 < 9.0.0`.

Supported OS matrix (from `metadata.json`): CentOS 9/10; RedHat 8/9/10;
OracleLinux 8/9/10; Rocky 8/9/10; AlmaLinux 8/9/10.

## Repository layout

- `manifests/init.pp` — the `libreswan` class (orchestration + all
  `config setup` parameters).
- `manifests/install.pp`, `manifests/service.pp`, `manifests/config.pp` —
  private install/service/config classes.
- `manifests/config/firewall.pp` — private; firewalld-vs-iptables rules.
- `manifests/config/pki.pp`, `manifests/config/pki/nsspki.pp` — PKI cert copy +
  NSS load.
- `manifests/connection.pp` — the public `libreswan::connection` define (tunnel
  API).
- `manifests/nss/{init_db,loadcacerts,loadcerts}.pp` — NSS DB plumbing defines.
- `types/` — custom data types: `Libreswan::ConnAddr`, `Libreswan::Interfaces`,
  `Libreswan::VirtualPrivate`, `Libreswan::Ip::V4::Virtualprivate`,
  `Libreswan::Ip::V6::Virtualprivate`.
- `templates/etc/ipsec.conf.erb` → `/etc/ipsec.conf`;
  `templates/etc/ipsec.d/connection.conf.erb` → each `conn` stanza;
  `templates/etc/ipsec.d/policies/*.erb` → the five policy-group files.
- `data/common.yaml`, `data/os/RedHat.yaml`, `data/os/RedHat-8.yaml` — module
  data (the required `$service_name`/`$package_name`/`$nssdir` and the
  OS-specific `nss::init_db::init_command`); `hiera.yaml` is the v5 hierarchy.
- `metadata.json` — deps, OS matrix, OpenVox requirement.
- `spec/classes/`, `spec/defines/` — rspec-puppet unit tests.
- `spec/acceptance/suites/default/` — beaker acceptance suite; nodesets under
  `spec/acceptance/nodesets/`.
- No `lib/` — the module defines no custom Ruby types/providers/functions/facts.
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
`simp-rspec-puppet-facts ~> 4.0.0`, `simp-beaker-helpers ~> 3.1`,
`rubocop ~> 1.85`. `spec/spec_helper.rb` requires
`voxpupuli/test/spec_helper` (this module has moved to the voxpupuli-test
harness rather than `puppetlabs_spec_helper`).

## Conventions

- Define tunnels with `libreswan::connection`; use the `'default'` title for
  shared `conn %default` settings.
- Route SIMP feature toggles through
  `simplib::lookup('simp_options::*', { 'default_value' => ... })` rather than
  assuming `simp_options` is included.
- Keep OS-specific values (`service_name`, `package_name`, `nssdir`,
  `nss::init_db::init_command`) in `data/os/*.yaml`, not hard-coded in manifests.
- Guard the firewall backend on `iptables::use_firewalld` and keep both the
  firewalld and iptables paths in sync when adding a rule
  (`config/firewall.pp`).
- Preserve the `@summary` / `@param` puppet-strings docstrings — they drive
  `REFERENCE.md`. Regenerate `REFERENCE.md` after changing docs or parameters.
- `Gemfile`, `spec/spec_helper.rb`, and `.github/workflows/pr_tests.yml` carry a
  **puppetsync** notice — they are baseline-managed and the next sync overwrites
  local edits. Push changes to those files upstream to the baseline, not here.
- Match the existing 2-space Puppet indentation and aligned-arrow parameter
  style used in `manifests/`.
