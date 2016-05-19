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

This module installs the Libreswan package on RedHat 7 systems and help configures IPSEC on the system.

## This is a SIMP module
This module is a component of the [System Integrity Management Platform](https://github.com/NationalSecurityAgency/SIMP), a compliance-management framework built on Puppet.

If you find any issues, they can be submitted to our [JIRA](https://simp-project.atlassian.net/).

Please read our [Contribution Guide](https://simp-project.atlassian.net/wiki/display/SD/Contributing+to+SIMP) and visit our [developer wiki](https://simp-project.atlassian.net/wiki/display/SD/SIMP+Development+Home).

This module is optimally designed for use within a larger SIMP ecosystem, but it can be used independently:
* When included within the SIMP ecosystem, security compliance settings will be managed from the Puppet server.
* If used independently, all SIMP-managed security subsystems are disabled by default and must be explicitly opted into by administrators.  Please review the `client_nets` and `$enable_*` parameters in `manifests/init.pp` for details.


## Module Description

This module installis the libreswan IPSEC service. IPSEC is Internet Protocol SECurity. It uses strong cryptography to provide both authentication and encryption services.

This module installes libreswan 3.17 and works with RedHat 7.
It will configure the IPSEC deamon using the most up to date defaults and, if you are using SIMP, manage your certificates. Connections can be managed through the puppet modules or by hand.

## Setup


* The package libreswan, current version 3.17, is installed.  The NSS pacakges need to also be installed.
* You will need the standard SIMP libraries installed.
* The module will install and configure a service named "ipsec", but which shows in the process list as "pluto".  The configuration file for the service is /etc/ipsec.conf.
* The configuration files for the connects which are brought up and handled by the service are located in /etc/ipsec.d by default.  This directory by default holds the NSS database.
* By default the ipsec service logs to syslog.


### Beginning with ipsec

Before installing pupmod-simp-libreswan make sure you read the libreswan documentation thouroughly.  It is located at https://libreswan.org/wiki/Introduction. After reading the introduction select the Main Wiki Page link to get to the user documentation:
https://libreswan.org/wiki/Main_Page#User_Documentation

## Usage

### Setting up the IPSEC service.
After reading the documentation, the ipsec service can be installed and configured on the system by adding the ipsec class to the client's hiera class list. If you have the firewall enabled you will want to add a setting for the networks that will be allowed to connect to your VPN.  This is varial=ble ipsec::ipsec_client_nets and defaults to ['127.0.0.1/32'].  Your hiera file should look something like:
--
ipsec::client_nets : "['192.168.122.0/24','192.168.123.0/24']"

classes:
 - 'libreswan'

The ipsec.conf file config section is setup during the install.  Most of the defaults describe in the documentation are used. (https://libreswan.org/man/ipsec.conf.5.html)  To see which defaults are over written, look at the init.pp manifests parameters.  Anything parameter with a default is either required or it is being over written.  To change defaults add setting to your clients hiera yaml file. (Note:  Connetion paramenters, the conn section, are not set up here.  They are set up when you add a connection.  It will fail if you try to set them up this way.)

By default the hiera yaml files are located in /etc/puppet/environments/production/hieradata/hosts/clientname.fully.qualified.domain.name.yaml.  A setting is added by putting a line in the top section before the classes)  in the format
modulename::parameter : setting

### Setting up an IPSEC connection.

To set up the an IPSEC connection, again, first read the libreswan user documentation linked above.  Other helpful links are:

https://libreswan.org/wiki/Configuration_examples
https://libreswan.org/man/ipsec.conf.5.html (the conn section.)

To add a connection you can either manually add  file to the ipsec directory (ipsec::ipsecdir  set to default /etc/ipsec.d in the configuration file of the ipsec service.)

To add a connection via puppet, create a definition file under the site manifest.  A simple VPN tunnel host to host example is given here, named ipsec_tunnel1.pp:

class site::ipsectunnel1 {
  include 'libreswan'

  libreswan::add_connection{ 'default':
     ipsec_tunnel::add_connection{ 'default':
    leftcert => "${::fqdn}",
    left   => '10.0.71.143',
    leftrsasigkey     => '%cert',
    leftsendcert      => 'always',
     notify => Service['ipsec'],
    authby  => 'rsasig'
  }

  libreswan::add_connection{ 'outgoing' :
     right  => '10.0.71.142',
     rightrsasigkey     => '%cert',
     notify => Service['ipsec'],
     auto => 'start'
  }

}

This will add two files to the ipsec directory, default.conf and outgoing.conf.  These are the connection files that will be read by the ipsec deamon and run.  Again, see the documentation for details on how to create the *.conf file for your system.  At this time not all conn options are available.  You can add *.conf files manually and puppet will not erase them.  Because of this, if you delete a add_connection call from the site manifest it will not delete the corresponding *.conf file, you must remove it manually.




## Reference

Module                    Purpose
ipsec                     Sets up parameters for the system and
                          calls installation and configuration
                          modules and maintains most dependancied beween them.
                          Configures IPSEC to point to a specific NSS database
                          then initiates calls to NSS routines to set up the
                          nss database.
ipsec::install            Installes the libreswan module and copies scripts to
                          needed by other modules to local system.
ipsec::config             Sets up ipsec directories and configures ipsec.conf file
ipsec::config::firewall           Configures the firewall setting for ipsec
ipsec::service            Sets up the ipsec service on the system.
ipsec::config::pki        Copies the certificates localy for use with ipsec.
ipsec::nsspki             Call NSS to load certs for ipsec use.
ipsec::nss::init_db       Sets up a local copy of NSS database and sets up files used
                          to access it.
ipsec::nss::loadcerts     Actually load the certificates to the NSS database.
------------------------
ipsec::add_connection     defines connections for IPSEC.


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
