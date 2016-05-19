
# Ensures that there are PKI certificates readable by the ipsec user in
#
class ipsec_tunnel::config::pki {
  assert_private()

  file { $::ipsec_tunnel::certsource:
    ensure =>  directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0700'
  }
  if $::ipsec_tunnel::use_simp_pki {
    include '::pki'
    ::pki::copy { $::ipsec_tunnel::certsource:
        notify  => Class['ipsec_tunnel::nsspki'],
        require => File["$::ipsec_tunnel::certsource"]
    }
  }
}

