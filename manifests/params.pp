# == Class libreswan::params
#
# This class is meant to be called from ipsec.
# It sets variables according to platform.
#
class libreswan::params {

# set the token for the NSS database.

  if $::libreswan::use_fips {
    $token = 'NSS FIPS 140-2 Certificate DB' }
  else {
    $token = 'NSS Certificate DB' }

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
