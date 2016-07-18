# == Class libreswan::config::firewall
#
# This class is meant to be called from ipsec.
# It ensures that firewall rules are defined.
#
class libreswan::config::firewall {
  assert_private()
  iptables::add_udp_listen { 'ipsec_allow':
    client_nets => $libreswan::ipsec_client_nets,
    apply_to    => 'all',
    dports      => [ $::libreswan::ikeport, $::libreswan::nat_ikeport ],
  }
# Add rules to allow the AH and ESP protocols used to encrypt data
  iptables::add_rules { 'allow_protocol_50':
    content  => '-A LOCAL-INPUT -p 50   -j ACCEPT',
    apply_to => all,
    order    => 15,
  }

  iptables::add_rules { 'allow_protocol_51':
    content  => '-A LOCAL-INPUT -p 51   -j ACCEPT',
    apply_to => all,
    order    => 15,
  }
}
