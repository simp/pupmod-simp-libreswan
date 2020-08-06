# This class is meant to be called from ipsec.
# It ensures that firewall rules are defined.
#
class libreswan::config::firewall {
  assert_private()

  $use_firewalld = simplib::lookup('iptables::use_firewalld', { 'default_value' => iptables::use_firewalld(true) })

  if $use_firewalld {
    simp_firewalld::rule { 'ipsec_allow':
      trusted_nets => $::libreswan::trusted_nets,
      apply_to     => 'all',
      dports       => [
        $::libreswan::ikeport,
        $::libreswan::nat_ikeport,
      ],
      protocol     => 'udp',
    }

    simp_firewalld::rule { 'allow_protocol_esp':
      trusted_nets => $::libreswan::trusted_nets,
      apply_to     => 'all',
      protocol     => 'esp',
      order        => 15,
    }

    simp_firewalld::rule { 'allow_protocol_ah':
      trusted_nets => $::libreswan::trusted_nets,
      apply_to     => 'all',
      protocol     => 'ah',
      order        => 15,
    }
  }
  else {
    iptables::listen::udp { 'ipsec_allow':
      trusted_nets => $libreswan::trusted_nets,
      apply_to     => 'all',
      dports       => [
        $::libreswan::ikeport,
        $::libreswan::nat_ikeport,
      ],
    }

    # Add rules to allow the AH and ESP protocols used to encrypt data
    iptables::rule { 'allow_protocol_esp':
      content  => '-A LOCAL-INPUT -p esp  -j ACCEPT',
      apply_to => 'all',
      order    => 15,
    }

    iptables::rule { 'allow_protocol_ah_ipv4':
      content  => '-A LOCAL-INPUT -p ah   -j ACCEPT',
      apply_to => 'ipv4',
      order    => 15,
    }

    iptables::rule { 'allow_protocol_ah_ipv6':
      content  => '-A LOCAL-INPUT -m ah   -j ACCEPT',
      apply_to => 'ipv6',
      order    => 15,
    }
  }
}
