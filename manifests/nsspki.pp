# == Class ipsec::nsspki
#
#  If simp is enabled to  manage the PKI certificates
#  This class will load the certs  from where they were
#  copied to in pki.pp (certsource) into the NSS database.
#
#  If simp is not managing certificates this does nothing.
#
# == Parameters
#
class ipsec::nsspki
{

#  IPSEC Module variables used in this  Class
  $dbdir = $::ipsec::ipsecdir
  $passwdfile = "${::ipsec::ipsecdir}/nsspassword"
  $cacert =  "${::ipsec::certsource}/pki/cacerts/cacerts.pem"
  $cert = "${::ipsec::certsource}/pki/public/${::fqdn}.pub"
  $key =  "${::ipsec::certsource}/pki/private/${::fqdn}.pem"
  $use_simp_pki = $::ipsec::use_simp_pki

  if $use_simp_pki {
    ipsec::nss::loadcerts{ "CA_for_${::domain}" :
      cert        => $cacert,
      cacert      => true,
      dbdir       => $dbdir,
      token       => $::ipsec::token,
      nsspwd_file => $passwdfile,
      subscribe   => Class['::ipsec::config::pki'],
    }
    ipsec::nss::loadcerts{ $::fqdn :
      dbdir       => $dbdir,
      nsspwd_file => $passwdfile,
      cert        => $cert,
      key         => $key,
      token       => $::ipsec::token,
      subscribe   => Class['::ipsec::config::pki'],
    }
  }
}
