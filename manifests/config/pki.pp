
# Ensures that there are PKI certificates readable by the ipsec user in
#
class ipsec::config::pki {
  assert_private()

  file { $::ipsec::certsource:
    ensure =>  directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0700'
  }
  if $::ipsec::use_simp_pki {
    include '::pki'
    ::pki::copy { $::ipsec::certsource:
        notify  => Class['ipsec::nsspki'],
        require => File[$::ipsec::certsource]
    }
  }
}

