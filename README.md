[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html) [![Build Status](https://travis-ci.org/simp/pupmod-simp-libreswan.svg)](https://travis-ci.org/simp/pupmod-simp-libreswan) [![SIMP compatibility](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)

#### Table of Contents

1. [Overview](#overview)
2. [Module Description - What the module does and why it is useful](#module-description)
3. [Setup - The basics of getting started with ipsec](#setup)
    * [What ipsec affects](#what-ipsec-affects)
    * [Setup requirements](#setup-requirements)
    * [Beginning with ipsec](#beginning-with-ipsec)
4. [Usage - Configuration options and additional functionality](#usage)
5. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
5. [Limitations - OS compatibility, etc.](#limitations)
6. [Development - Guide for contributing to the module](#development)
      * [Acceptance Tests - Beaker env variables](#acceptance-tests)

## Overview

This module installs and configures Libreswan, an implementation of the VPN protocol, which supports IPSEC and IKE.

## This is a SIMP module

This module is a component of the [System Integrity Management Platform](https://github.com/NationalSecurityAgency/SIMP), a compliance-management framework built on Puppet.

If you find any issues, they can be submitted to our [JIRA](https://simp-project.atlassian.net/).

Please read our [Contribution Guide](https://simp-project.atlassian.net/wiki/display/SD/Contributing+to+SIMP) and visit our [developer wiki](https://simp-project.atlassian.net/wiki/display/SD/SIMP+Development+Home).

This module is optimally designed for use within a larger SIMP ecosystem, but it can be used independently:
* When included within the SIMP ecosystem, security compliance settings will be managed from the Puppet server.
* If used independently, all SIMP-managed security subsystems are disabled by default and must be explicitly opted into by administrators.  Please review the the `client_nets`, `simp_firewall`, `nssdb_password`, and
 `use_*` parameters in `manifests/init.pp` for details.

## Module Description

This module installs the libreswan IPSEC service. IPSEC is Internet Protocol SECurity. It uses strong cryptography to provide both authentication and encryption services.

This module installs the most recently RedHat approved version of libreswan, currently  3.15.
It will configure the IPSEC deamon using the most up to date defaults and, if you are using SIMP, manage your certificates. Connections can be managed through the puppet modules or by hand.


## Beginning with ipsec
Before installing pupmod-simp-libreswan make sure you read the [libreswan documentation](https://libreswan.org/wiki/Introduction) thouroughly. After reading the introduction select the [Main Wiki Page](https://libreswan.org/wiki/Main_Page#User_Documentation) link to get to the user documentation.

All ipsec.conf options can be found on the manpage "man ipsec.conf"


## Setup
* Ensure the libreswan and NSS packages are available.

Before installing pupmod-simp-libreswan make sure you read the libreswan documentation thouroughly.  It is located at https://libreswan.org/wiki/Introduction. After reading the introduction select the Main Wiki Page link to get to the user documentation:
https://libreswan.org/wiki/Main_Page#User_Documentation

### Defaults
* IPSEC configuration file: `/etc/ipsec.conf`
* Configuration directory: `/etc/ipsec.d/`
* NSS database (containing peer certs and the CA):` /etc/ipsec.d/[key4.db,cert9.db,pkcs11.txt]`
* Policy files (clear, private): `/etc/ipsec.d/policies/`
* Secrets files (secret or key used by ipsec): `/etc/ipsec.d/*.secrets`
* Connection files (tunnel configurations): `/etc/ipsec.d/*.conf`
* Log file: `/var/log/secure`
* Libreswan starts an "ipsec" service, but it is listed as "pluto" in the process list.

### Configure the IPSEC service
Add the following to hiera:
```yaml
---
simp_options::pki: true
simp_options::trusted_nets : <desired client nets>

classes:
  - 'libreswan'
```

Make sure that you have all Certificate Authorities needed loaded into SIMP.  If the side you are connecting to
uses a different CA from yours, make sure you load their CA into your CA listing in PKI.  (See the SIMP
documentation to see how to do this.)

You can verify the contents of the nss database with:
```bash
certutil -L -d sql:/etc/ipsec.d/
```

### Setting up an IPSEC connection.


To add a connection via puppet, create a definition file under the site manifest.  A simple VPN tunnel host to host example is given here, named `ipsec_tunnel1.pp`:

```ruby
class site::ipsectunnel1 {
  include 'libreswan'

  libreswan::connection{ 'default':
    leftcert => "${::fqdn}",
    left   => "${ipaddress}"
    leftrsasigkey     => '%cert',
    leftsendcert      => 'always',
    authby  => 'rsasig'
  }

  libreswan::connection{ 'outgoing' :
     right  => '<the IP Address of the client you are connecting to.>'
     rightrsasigkey     => '%cert',
     notify => Service['ipsec'],
     auto => 'start'
  }

}

```
This will add two files to the `ipsec` directory, `default.conf` and `outgoing.conf`.  These are the connection files that will be read by the ipsec daemon and run.

**NOTE**: If you delete a connection from the site manifest, it will not know to delete it from
the directory.  You will need to remove it manually.


## Reference
|Module                   | Purpose |
|-------------------------|---------|
| `ipsec`                     | Sets up parameters for the system and calls installation and configuration modules and maintains most dependancied beween them. Configures IPSEC to point to a specific NSS database then initiates calls to NSS routines to set up the nss database. |
| `ipsec::install`            | Installs the libreswan module and copies scripts to needed by other modules to local system. |
| `ipsec::config`             | Sets up ipsec directories and configures `ipsec.conf` file |
| `ipsec::config::firewall`   | Configures the firewall setting for ipsec |
| `ipsec::service`            | Sets up the ipsec service on the system. |
| `ipsec::config::pki`        | Copies the certificates localy for use with ipsec. |
| `ipsec::nsspki`             | Call NSS to load certs for ipsec use. |
| `ipsec::nss::init_db`       | Sets up a local copy of NSS database and sets up files used to access it. |
| `ipsec::nss::loadcerts`     | Actually load the certificates to the NSS database. |
| `ipsec::connection`         | defines connections for IPSEC. |



## Limitations

Currently this has only been tested with Centos 6 and 7.

## Development

Please see the [SIMP Contribution Guidelines](https://simp-project.atlassian.net/wiki/display/SD/Contributing+to+SIMP).

### Acceptance tests

****  Section Not Complete ****
To run the system tests, you need [Vagrant](https://www.vagrantup.com/) installed. Then, run:

```shell
bundle exec rake acceptance
```

Some environment variables may be useful:

```shell
BEAKER_debug=true
BEAKER_provision=no
BEAKER_destroy=no
BEAKER_use_fixtures_dir_for_modules=yes
```

* `BEAKER_debug`: show the commands being run on the STU and their output.
* `BEAKER_destroy=no`: prevent the machine destruction after the tests finish so you can inspect the state.
* `BEAKER_provision=no`: prevent the machine from being recreated. This can save a lot of time while you're writing the tests.
* `BEAKER_use_fixtures_dir_for_modules=yes`: cause all module dependencies to be loaded from the `spec/fixtures/modules` directory, based on the contents of `.fixtures.yml`.  The contents of this directory are usually populated by `bundle exec rake spec_prep`.  This can be used to run acceptance tests to run on isolated networks.
