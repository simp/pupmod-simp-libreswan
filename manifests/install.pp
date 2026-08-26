# @summary Install the libreswan package.
#
class libreswan::install {
  assert_private()

  package { $libreswan::package_name:
    ensure => present,
  }
}
