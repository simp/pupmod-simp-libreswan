
# Ensures that there are PKI certificates readable by the ipsec user in
#
class libreswan::config::pki {
  assert_private()

  file { $::libreswan::certsource:
    ensure =>  directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0700'
  }
  if $::libreswan::use_simp_pki {
    include '::pki'
    ::pki::copy { $::libreswan::certsource:
        notify  => Class['libreswan::nsspki'],
        require => File[$::libreswan::certsource]
    }
  }
}

