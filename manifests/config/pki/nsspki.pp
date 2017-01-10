# This class will ensure that the PKI certificates are loaded into the
# NSS Database used by the IPSEC process. It is called when the certificates
# change or when the data base is initialized.
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

  libreswan::nss::init_db { "NSSDB ${::libreswan::ipsecdir}":
    dbdir       => $::libreswan::ipsecdir,
    password    => $::libreswan::nssdb_password,
    nsspassword => $::libreswan::nsspassword,
    token       => $::libreswan::token,
    fips        => $::libreswan::fips,
    require     => File['/etc/ipsec.conf'],
  }

  libreswan::nss::loadcacerts{ "CA_for_${::domain}" :
    cert        => $::libreswan::config::pki::app_pki_ca,
    dbdir       => $::libreswan::ipsecdir,
    token       => $::libreswan::token,
    nsspwd_file => $::libreswan::nsspassword,
    subscribe   => [Pki::Copy[$::libreswan::app_pki_dir],Libreswan::Nss::Init_db["NSSDB ${::libreswan::ipsecdir}"]]
  }
  libreswan::nss::loadcerts{ $::fqdn :
    dbdir       => $::libreswan::ipsecdir,
    nsspwd_file => $::libreswan::nsspassword,
    cert        => $::libreswan::config::pki::app_pki_cert,
    key         => $::libreswan::config::pki::app_pki_key,
    token       => $::libreswan::token,
    subscribe   => [Pki::Copy[$::libreswan::app_pki_dir],Libreswan::Nss::Init_db["NSSDB ${::libreswan::ipsecdir}"]]
  }
}

