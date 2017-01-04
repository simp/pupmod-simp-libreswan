# This class will ensure that the PKI certificates are loaded into the
# NSS Database used by the IPSEC process.
# It is called when the certificates change or when the data
# base is initialized.
#
class libreswan::config::pki::nsspki(
) {
  assert_private()
  Class['libreswan::config::pki'] ~> Class['libreswan::config::pki::nsspki']

  # Currently for libreswan version 3.15 the secrets file must be
  # updated with name of the certificate to use from the NSS database.
  file { $::libreswan::secretsfile:
    ensure  => file,
    owner   => root,
    mode    => '0400',
    content => ": RSA \"${::fqdn}\"",
  }

  $loadcerts_subscribe = $::libreswan::pki ? {
    'simp'  => [Pki::Copy[$::libreswan::app_pki_dir],Libreswan::Nss::Init_db["NSSDB ${::libreswan::ipsecdir}"]],
    default => Libreswan::Nss::Init_db["NSSDB ${::libreswan::ipsecdir}"]
  }
  if $::libreswan::pki {
    libreswan::nss::loadcacerts{ "CA_for_${::domain}" :
      cert        => $::libreswan::config::pki::app_pki_ca,
      dbdir       => $::libreswan::ipsecdir,
      token       => $::libreswan::token,
      nsspwd_file => $::libreswan::nsspassword,
      subscribe   => $loadcerts_subscribe
    }
    libreswan::nss::loadcerts{ $::fqdn :
      dbdir       => $::libreswan::ipsecdir,
      nsspwd_file => $::libreswan::nsspassword,
      cert        => $::libreswan::config::pki::app_pki_cert,
      key         => $::libreswan::config::pki::app_pki_key,
      token       => $::libreswan::token,
      subscribe   => $loadcerts_subscribe
    }
  } else {
    libreswan::nss::loadcacerts{ "CA_for_${::domain}" :
      cert        => $::libreswan::config::pki::app_pki_ca,
      dbdir       => $::libreswan::ipsecdir,
      token       => $::libreswan::token,
      nsspwd_file => $::libreswan::nsspassword,
      subscribe   => [File[$::libreswan::config::pki::app_pki_ca],Libreswan::Nss::Init_db["NSSDB ${::libreswan::ipsecdir}"]]
    }
    libreswan::nss::loadcerts{ $::fqdn :
      dbdir       => $::libreswan::ipsecdir,
      nsspwd_file => $::libreswan::nsspassword,
      cert        => $::libreswan::config::pki::app_pki_cert,
      key         => $::libreswan::config::pki::app_pki_key,
      token       => $::libreswan::token,
      subscribe   => [File[$::libreswan::config::pki::app_pki_cert],File[$::libreswan::config::pki::app_pki_key],Libreswan::Nss::Init_db["NSSDB ${::libreswan::ipsecdir}"]]
    }
  }
}

