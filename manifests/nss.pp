# @summary Install the NSS password-update helper used by `libreswan::nss::init_db`.
#
# Included automatically by `libreswan::nss::init_db`. Not declared on a bare
# `include libreswan`.
#
class libreswan::nss {
  file { '/usr/local/scripts':
    ensure => directory,
    owner  => root,
    mode   => '0755',
  }
  file { '/usr/local/scripts/nss':
    ensure => directory,
    owner  => root,
    mode   => '0755',
  }
  file { '/usr/local/scripts/nss/update_nssdb_password.sh':
    ensure => file,
    owner  => root,
    mode   => '0500',
    source => 'puppet:///modules/libreswan/usr/local/scripts/nss/update_nssdb_password.sh',
  }
}
