# If use_simp-pki is set this module will ensure that there
# the PKI certificates are loaded into the NSS Database used
# by the IPSEC process.
#
class libreswan::config::pki {
  assert_private()

  $cacert = "${::libreswan::certsource}/pki/cacerts/cacerts.pem"
  $cert   = "${::libreswan::certsource}/pki/public/${::fqdn}.pub"
  $key    = "${::libreswan::certsource}/pki/private/${::fqdn}.pem"

  libreswan::nss::init_db { "NSSDB ${::libreswan::ipsecdir}":
    dbdir        =>  $::libreswan::ipsecdir,
    password     =>  $::libreswan::nssdb_password,
    nsspassword  =>  $::libreswan::nsspassword,
    token        =>  $::libreswan::token,
    use_fips     =>  $::libreswan::use_fips,
    require      =>  File['/etc/ipsec.conf'],
    notify       =>  Class[Libreswan::Config::Pki::Nsspki]
  }

  # Create the directory to  copy the certs to
  file { $::libreswan::certsource:
    ensure =>  directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0700'
  }

  # Copy the certs if they are updated and notify the Load
  # certificate routines.
  include '::pki'
  ::pki::copy { $::libreswan::certsource :
    source  => $::libreswan::pkiroot,
    notify  => Class[Libreswan::Config::Pki::Nsspki],
    require => File[$::libreswan::certsource]
  }
}

