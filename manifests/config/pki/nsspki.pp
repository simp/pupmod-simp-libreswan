# This class will ensure that the PKI certificates are loaded into the
# NSS Database used by the IPSEC process.
# It is called when the certificates change or when the data
# base is initialized.
#
class libreswan::config::pki::nsspki(
) {

  assert_private()
  Class[Libreswan::Config::Pki] ~> Class[Libreswan::Config::Pki::Nsspki]

  $cacert = $::libreswan::config::pki::app_pki_ca
  $cert   = $::libreswan::config::pki::app_pki_cert
  $key    = $::libreswan::config::pki::app_pki_key
  $pki    = $::libreswan::pki
  $dbdir  = $::libreswan::ipsecdir

  # Currently for libreswan version 3.15 the secrets file must be
  # updated with name of the certificate to use from the NSS database.
  file { $::libreswan::secretsfile:
    ensure  => file,
    owner   => root,
    mode    => '0400',
    content => ": RSA \"${::fqdn}\"",
  }

  if $pki {
    libreswan::nss::loadcacerts{ "CA_for_${::domain}" :
      cert        => $cacert,
      dbdir       => $::libreswan::ipsecdir,
      token       => $::libreswan::token,
      nsspwd_file => $::libreswan::nsspassword,
      subscribe   => [Pki::Copy["${::libreswan::app_pki_dir}"],Libreswan::Nss::Init_db["NSSDB ${dbdir}"]]
    }
    libreswan::nss::loadcerts{ $::fqdn :
      dbdir       => $::libreswan::ipsecdir,
      nsspwd_file => $::libreswan::nsspassword,
      cert        => $cert,
      key         => $key,
      token       => $::libreswan::token,
      subscribe   => [Pki::Copy["${::libreswan::app_pki_dir}"],Libreswan::Nss::Init_db["NSSDB ${dbdir}"]]
    }
  } else {
    libreswan::nss::loadcacerts{ "CA_for_${::domain}" :
      cert        => $cacert,
      dbdir       => $::libreswan::ipsecdir,
      token       => $::libreswan::token,
      nsspwd_file => $::libreswan::nsspassword,
      subscribe   => [File["${cacert}"],Libreswan::Nss::Init_db["NSSDB ${dbdir}"]]
    }
    libreswan::nss::loadcerts{ $::fqdn :
      dbdir       => $::libreswan::ipsecdir,
      nsspwd_file => $::libreswan::nsspassword,
      cert        => $cert,
      key         => $key,
      token       => $::libreswan::token,
      subscribe   => [File["${cert}"],File["${key}"],Libreswan::Nss::Init_db["NSSDB ${dbdir}"]]
    }
  }
}

