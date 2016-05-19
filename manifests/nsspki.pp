# == Class ipsec_tunnel::nsspki
#
#  If simp is enabled to  manage the PKI certificates
#  This class will load the certs  from where they were
#  copied to in pki.pp (certsource) into the NSS database.
#
#  If simp is not managing certificates this does nothing.
#
# == Parameters
#
class ipsec_tunnel::nsspki
{

#  IPSEC Module variables used in this  Class
  $dbdir = $::ipsec_tunnel::ipsecdir
  $passwdfile = "${::ipsec_tunnel::ipsecdir}/nsspassword"
  $cacert =  "${::ipsec_tunnel::certsource}/pki/cacerts/cacerts.pem"
  $cert = "${::ipsec_tunnel::certsource}/pki/public/${::fqdn}.pub"
  $key =  "${::ipsec_tunnel::certsource}/pki/private/${::fqdn}.pem"
  $use_simp_pki = $::ipsec_tunnel::use_simp_pki

  if $use_simp_pki {
    ipsec_tunnel::nss::loadcerts{ "CA_for_${::domain}" :
      cert        => $cacert,
      cacert      => true,
      dbdir       => $dbdir,
      token       => $::ipsec_tunnel::token,
      nsspwd_file => $passwdfile,
      subscribe   => Class['::ipsec_tunnel::config::pki'],
    }
    ipsec_tunnel::nss::loadcerts{ $::fqdn :
      dbdir       => $dbdir,
      nsspwd_file => $passwdfile,
      cert        => $cert,
      key         => $key,
      token       => $::ipsec_tunnel::token,
      subscribe   => Class['::ipsec_tunnel::config::pki'],
    }
  }
}
