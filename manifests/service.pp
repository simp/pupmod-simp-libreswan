# @summary Ensure that the appropriate services are running.
#
class libreswan::service {
  assert_private()

  service { $libreswan::service_name:
    ensure     => running,
    enable     => true,
    hasstatus  => true,
    hasrestart => true,
  }
}
