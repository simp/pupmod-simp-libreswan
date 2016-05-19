# == Class ipsec::service
#
# This class is meant to be called from ipsec.
# It ensure the service is running.
#
class ipsec::service {
  assert_private()

  service { $::ipsec::service_name:
    ensure     => running,
    enable     => true,
    hasstatus  => true,
    hasrestart => true,
  }
}
