[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html) [![Build Status](https://travis-ci.org/simp/pupmod-simp-ipsec.svg)](https://travis-ci.org/simp/pupmod-simp-ipsec) [![SIMP compatibility](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)

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
* If used independently, all SIMP-managed security subsystems are disabled by default and must be explicitly opted into by administrators.  Please review the `client_nets` and `$enable_*` parameters in `manifests/init.pp` for details.

## Module Description

This module installs and configures libreswan 3.17 in RedHat 7.

It will configure the IPSEC deamon using the most up to date defaults and, if you are using SIMP, manage your certificates. Connections can be managed through the puppet modules or by hand.

## Beginning with ipsec

Before installing pupmod-simp-ipsec make sure you read the [libreswan documentation](https://libreswan.org/wiki/Introduction) thouroughly. After reading the introduction select the [Main Wiki Page](https://libreswan.org/wiki/Main_Page#User_Documentation) link to get to the user documentation.

All ipsec.conf options can be found on the manpage "man ipsec.conf"

## Setup

* Ensure the libreswan and NSS packages are available.  Currently, libreswan 3.17 is supported.

### Defaults

* IPSEC configuration file: /etc/ipsec.conf
* Configuration directory: /etc/ipsec.d/
* NSS database (containing peer certs and the CA): /etc/ipsec.d/[key4.db,cert9.db,pkcs11.txt]
* Policy files (clear, private): /etc/ipsec.d/policies/
* Secrets files (secret or key used by ipsec): /etc/ipsec.d/*.secrets
* Connection files (tunnel configurations): /etc/ipsec.d/*.conf
* Log file: /var/log/secure 
* Libreswan starts an "ipsec" service, but it is listed as "pluto" in the process list.

### Configure the IPSEC service

* Add the following to hiera:
```yaml
---
use_simp_pki: true
ipsec::client_nets : <desired client nets>

classes:
  - 'ipsec'
```

* Edit the policy files (see defaults) appropriately to force clear or private (encrypted)
connections on your client nets.

* Edit the secrets file (see defaults) to include the RSA private key for your 'left' connection:
```ruby
: RSA <name of 'left' connection cert, as it is in the NSS database>
```

### Configure an IPSEC connection

Once the IPSEC class is deployed with the desired configuration (see above), you can configure IPSEC
tunnels.

* Add the public key of all peers you wish to connect to ('right' connections), and their associated CAs,
to the NSS database of the 'left' connection.  Generate a pcks12 (.p12) file containing the public
cert and its corresponding CA of every 'right' connection, and use:
```bash
ipsec import <path to 'right' connection .p12>
```
NOTE: Once you deploy the IPSEC class via SIMP, a .p12 file containing the peer's public cert and CA will
be auto generated in /etc/ipsec.d/pki/.  Securly copy this file to peers as needed, to avoid manually
creating .p12 files.

You can verify the contents of the nss database with:
```bash
certutil -L -d sql:/etc/ipsec.d/
```

* Create an IPSEC tunnel, utilizing ESP.  Add the following content to a site manifest and include on your
desired 'left' connection node:
```ruby
  ipsec::add_connection { 'some_connection_name':
    left => "${ipaddress}",
    leftcert => "${::fqdn}",
    leftrsasigkey => '%cert',
    leftsendcert => 'always',
    right => '<some.peer.fqdn>',
    rightcert => '<name of peer cert as it was added to the NSS database>',
    rightrsasigkey => '%cert',
    notify => Service['ipsec'],
    auto => 'start',
    authby => 'rsasig',
    ike => 'aes-sha256;dh24',
    phase2alg => 'aes-sha256;dh24'
  }
```
Invert left/right, leftcert/rightcert, and include the inverted manifest on the 'right' connection node.

* Restart the "ipsec" service on both peers.  If everything is configured correctly, traffic between the left and right
connections should be carried and encrypted by IPSEC.

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
| `ipsec::add_connection`     | defines connections for IPSEC. |


## Limitations

Currently this has only been tested with RedHat 7.

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
