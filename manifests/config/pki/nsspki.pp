# This class will ensure that the
# the PKI certificates are loaded into the NSS Database used
# by the IPSEC process.
# It is called when the certificates change or when the data
# base is initialized.
#
class libreswan::config::pki::nsspki {
  assert_private()

  $cacert = "${::libreswan::certsource}/pki/cacerts/cacerts.pem"
  $cert   = "${::libreswan::certsource}/pki/public/${::fqdn}.pub"
  $key    = "${::libreswan::certsource}/pki/private/${::fqdn}.pem"


  # Currently for version 3.15 the secrets file must be updated with
  # name of the certificate to use from the NSS database.
  file { $::libreswan::secretsfile:
    ensure  => file,
    owner   => root,
    mode    => '0400',
    content => ": RSA \"${::fqdn}\"",
  }

  libreswan::nss::loadcacerts{ "CA_for_${::domain}" :
    cert        => $cacert,
    dbdir       => $::libreswan::ipsecdir,
    token       => $::libreswan::token,
    nsspwd_file => $::libreswan::nsspassword,
    subscribe   => [Pki::Copy[$::libreswan::certsource],Libreswan::Nss::Init_db["NSSDB ${::libreswan::ipsecdir}"]]
  }
  libreswan::nss::loadcerts{ $::fqdn :
    dbdir       => $::libreswan::ipsecdir,
    nsspwd_file => $::libreswan::nsspassword,
    cert        => $cert,
    key         => $key,
    token       => $::libreswan::token,
    subscribe   => [Pki::Copy[$::libreswan::certsource],Libreswan::Nss::Init_db["NSSDB ${::libreswan::ipsecdir}"]]
  }
}

