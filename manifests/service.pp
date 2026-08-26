# @summary Optionally manage the IPSEC service.
#
# By design, a bare `include libreswan` does NOT enable, start, or restart
# the IPSEC service. To have this module manage the service, set
# `libreswan::service_ensure` and/or `libreswan::service_enable`.
#
class libreswan::service {
  assert_private()

  $_attrs = {
    'ensure' => $libreswan::service_ensure,
    'enable' => $libreswan::service_enable,
  }.filter |$_, $v| { $v =~ NotUndef }

  if $_attrs.size > 0 {
    service { $libreswan::service_name:
      *          => $_attrs,
      hasstatus  => true,
      hasrestart => true,
    }
  }
}
