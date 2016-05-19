# == Class libreswan::nsspki
#
#  If simp is enabled to  manage the PKI certificates
#  This class will load the CA cert and the local machine cert
#  into the NSS database for the loaction that they were
#  copied to by pki.pp ($certsource).
#  When ever the certs are updated on the main puppet server, 
#  they will be automatically reloaded here.
#
#  If simp is not managing certificates this does nothing.
#  If you are managing your own certificates not through simp
#  then call the libreswan::nss::load* routines on your own.
#
# == Parameters
#
class libreswan::nsspki
{

#  IPSEC Module variables used in this  Class
  $dbdir = $::libreswan::ipsecdir
  $passwdfile = "${::libreswan::ipsecdir}/nsspassword"
  $cacert =  "${::libreswan::certsource}/pki/cacerts/cacerts.pem"
  $cert = "${::libreswan::certsource}/pki/public/${::fqdn}.pub"
  $key =  "${::libreswan::certsource}/pki/private/${::fqdn}.pem"
  $use_simp_pki = $::libreswan::use_simp_pki

  if $use_simp_pki {
    libreswan::nss::loadcerts{ "CA_for_${::domain}" :
      cert        => $cacert,
      cacert      => true,
      dbdir       => $dbdir,
      token       => $::libreswan::token,
      nsspwd_file => $passwdfile,
      subscribe   => Class['::libreswan::config::pki'],
    }
    libreswan::nss::loadcerts{ $::fqdn :
      dbdir       => $dbdir,
      nsspwd_file => $passwdfile,
      cert        => $cert,
      key         => $key,
      token       => $::libreswan::token,
      subscribe   => Class['::libreswan::config::pki'],
    }
  }
}
