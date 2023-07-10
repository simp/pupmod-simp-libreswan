# @summary Ensure that the PKI certificates are loaded into the NSS Database used by the IPSEC process.
#
# Called when the certificates change or when the database is initialized.
#
# @param certname
#   The name of the certificate to be used
#
class libreswan::config::pki::nsspki(
  String[1] $certname = $facts['networking']['fqdn'],
) {
  assert_private()
  Class['libreswan::config::pki'] ~> Class['libreswan::config::pki::nsspki']

  # Currently for libreswan version 3.15 the secrets file must be
  # updated with name of the certificate to use from the NSS database.
  file { $libreswan::secretsfile:
    ensure  => file,
    owner   => root,
    mode    => '0400',
    content => ": RSA \"${certname}\"",
  }

  $_fips = $libreswan::fips or $facts['fips_enabled']

  libreswan::nss::init_db { "NSSDB ${::libreswan::ipsecdir}":
    dbdir       => $libreswan::ipsecdir,
    password    => $libreswan::nssdb_password,
    nsspassword => $libreswan::nsspassword,
    token       => $libreswan::token,
    fips        => $_fips,
    require     => File['/etc/ipsec.conf'],
  }

  libreswan::nss::loadcacerts{ 'CA_for_connections' :
    cert        => $libreswan::config::pki::app_pki_ca,
    dbdir       => $libreswan::ipsecdir,
    token       => $libreswan::token,
    nsspwd_file => $libreswan::nsspassword,
    subscribe   => Libreswan::Nss::Init_db["NSSDB ${::libreswan::ipsecdir}"]
  }

  libreswan::nss::loadcerts{ $certname :
    dbdir       => $libreswan::ipsecdir,
    nsspwd_file => $libreswan::nsspassword,
    cert        => $libreswan::config::pki::app_pki_cert,
    key         => $libreswan::config::pki::app_pki_key,
    token       => $libreswan::token,
    subscribe   => Libreswan::Nss::Init_db["NSSDB ${::libreswan::ipsecdir}"]
  }
}

