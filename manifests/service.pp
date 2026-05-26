# @summary Optionally manage the IPSEC service.
#
# By design, a bare `include libreswan` does NOT enable, start, or restart
# the IPSEC service. To have this module manage the service, set
# `libreswan::service_ensure` and/or `libreswan::service_enable`.
#
class libreswan::service {
  assert_private()

  if $libreswan::service_ensure =~ NotUndef or $libreswan::service_enable =~ NotUndef {
    service { $libreswan::service_name:
      ensure     => $libreswan::service_ensure,
      enable     => $libreswan::service_enable,
      hasstatus  => true,
      hasrestart => true,
    }
  }
}
