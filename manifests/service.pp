# == Class ipsec_tunnel::service
#
# This class is meant to be called from ipsec_tunnel.
# It ensure the service is running.
#
class ipsec_tunnel::service {
  assert_private()

  service { $::ipsec_tunnel::service_name:
    ensure     => running,
    enable     => true,
    hasstatus  => true,
    hasrestart => true,
  }
}
