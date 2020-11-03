[![License](https://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/73/badge)](https://bestpractices.coreinfrastructure.org/projects/73)
[![Puppet Forge](https://img.shields.io/puppetforge/v/simp/libreswan.svg)](https://forge.puppetlabs.com/simp/libreswan)
[![Puppet Forge Downloads](https://img.shields.io/puppetforge/dt/simp/libreswan.svg)](https://forge.puppetlabs.com/simp/libreswan)
[![Build Status](https://travis-ci.org/simp/pupmod-simp-libreswan.svg)](https://travis-ci.org/simp/pupmod-simp-libreswan)

#### Table of Contents

<!-- vim-markdown-toc GFM -->

* [Overview](#overview)
* [This is a SIMP module](#this-is-a-simp-module)
* [Module Description](#module-description)
* [Beginning with ipsec](#beginning-with-ipsec)
* [Setup](#setup)
  * [Defaults](#defaults)
  * [Configure the IPSEC service](#configure-the-ipsec-service)
  * [Setting up an IPSEC connection.](#setting-up-an-ipsec-connection)
* [> delete it from the directory automatically.](#-delete-it-from-the-directory-automatically)
* [Reference](#reference)
* [Development](#development)
  * [Unit tests](#unit-tests)
  * [Acceptance tests](#acceptance-tests)

<!-- vim-markdown-toc -->

## Overview

This module installs and configures Libreswan, an implementation of the VPN protocol, which supports IPSEC and IKE.

## This is a SIMP module

This module is a component of the [System Integrity Management Platform](https://simp-project.com),
a compliance-management framework built on Puppet.

If you find any issues, they can be submitted to our [JIRA](https://simp-project.atlassian.net/).

Please read our [Contribution Guide](https://simp.readthedocs.io/en/stable/contributors_guide/index.html).

This module is optimally designed for use within a larger SIMP ecosystem, but it can be used independently:
* When included within the SIMP ecosystem, security compliance settings will be managed from the Puppet server.
* If used independently, all SIMP-managed security subsystems are disabled by
  default and must be explicitly opted into by administrators.  Please see
  parameters mapped to `simp_options::*` items in `init.pp` for details.

## Module Description

This module installs the libreswan IPSEC service. IPSEC is Internet Protocol SECurity. It uses strong cryptography to provide both authentication and encryption services.

This module installs the most recently RedHat approved version of libreswan, currently  3.15.
It will configure the IPSEC daemon using the most up to date defaults and, if you are using SIMP, manage your certificates. Connections can be managed through the puppet modules or by hand.


## Beginning with ipsec

Before installing `pupmod-simp-libreswan` make sure you read the [libreswan documentation](https://libreswan.org/wiki/Introduction) thouroughly. After reading the introduction select the [Main Wiki Page](https://libreswan.org/wiki/Main_Page#User_Documentation) link to get to the user documentation.

* All `ipsec.conf` options can be found in `ipsec.conf(5)`.


## Setup

* Ensure the libreswan and NSS packages are available.

Before installing pupmod-simp-libreswan make sure you read the libreswan documentation thoroughly.  It is located at https://libreswan.org/wiki/Introduction. After reading the introduction select the Main Wiki Page link to get to the user documentation:
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

You can verify the contents of the NSS database with:

```bash
certutil -L -d sql:/etc/ipsec.d/
```

### Setting up an IPSEC connection.


To add a connection via puppet, create a definition file under the site manifest.  A simple VPN tunnel host to host example is given here, named `ipsec_tunne1.pp`:

```puppet
class site::ipsec_tunne1 {
  include 'libreswan'

  libreswan::connection{ 'default':
    leftcert      => $facts['fqdn'],
    left          => $facts['ipaddress'],
    leftrsasigkey => '%cert',
    leftsendcert  => 'always',
    authby        => 'rsasig'
  }

  libreswan::connection{ 'outgoing' :
     right          => '<the IP Address of the client you are connecting to.>'
     rightrsasigkey => '%cert',
     notify         => Service['ipsec'],
     auto           => 'start'
  }
}
```
This will add two files to the `ipsec` directory, `default.conf` and `outgoing.conf`.  These are the connection files that will be used by the libreswan daemon.

----------------------------------------------------------------------
> **NOTE**: If you delete a connection from the site manifest, it will not
> delete it from the directory automatically.
----------------------------------------------------------------------

## Reference

See [REFERENCE.md](./REFERENCE.md)

## Development

Please read our [Contribution Guide](https://simp.readthedocs.io/en/stable/contributors_guide/index.html).

### Unit tests

Unit tests, written in `rspec-puppet` can be run by calling:

```shell
bundle exec rake spec
```

### Acceptance tests

To run the system tests, you need [Vagrant](https://www.vagrantup.com/) installed. Then, run:

```shell
bundle exec rake beaker:suites
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
