# This class is meant to be called from ipsec.
# It sets variables according to platform.
#
class libreswan::params {
  case $::osfamily {
    'RedHat': {
      $package_name = 'libreswan'
      $service_name = 'ipsec'
    }
    default: {
      fail("Module ${module_name} is not supported on ${::osfamily}")
    }
  }
}
