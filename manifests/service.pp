# This class is meant to be called from ipsec.
# It ensure the service is running.
#
class libreswan::service {
  assert_private()

  service { $::libreswan::service_name:
    ensure     => running,
    enable     => true,
    hasstatus  => true,
    hasrestart => true,
  }
}
