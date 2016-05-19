# == Class ipsec_tunnel::params
#
# This class is meant to be called from ipsec_tunnel.
# It sets variables according to platform.
#
class ipsec_tunnel::params {
  case $::osfamily {
    'RedHat': {
      $package_name = 'libreswan'
      $service_name = 'ipsec'
    }
    default: {
      fail("${::operatingsystem} not supported")
    }
  }
}
