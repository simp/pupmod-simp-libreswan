# == Class ipsec_tunnel::install
#
# This class is called from ipsec_tunnel for install.
#
#  The nss package is installed in simplib and can not be redeclared here.
#
class ipsec_tunnel::install {
  assert_private()

#Make sure Libreswan is installed
  package { $::ipsec_tunnel::package_name:
    ensure => present,
  }

#Install scripts for changing password

  file { '/usr/local/scripts':
    ensure => directory,
    owner  => root,
    mode   => '0755',
  }
  file { '/usr/local/scripts/nss':
    ensure => directory,
    owner  => root,
    mode   => '0755',
  }
  file { '/usr/local/scripts/nss/update_nssdb_password.sh':
    ensure => present,
    owner  => root,
    mode   => '0500',
    source => 'puppet:///modules/ipsec_tunnel/usr/local/scripts/nss/update_nssdb_password.sh'
  }
  file { "${::ipsec_tunnel::ipsecdir}" :
    ensure => directory,
    owner  => root,
    mode   => '0700',
  }

}
