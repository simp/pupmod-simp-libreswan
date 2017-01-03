# If use_simp-pki is set this module will ensure that there
# the PKI certificates are loaded into the NSS Database used
# by the IPSEC process.
#
class libreswan::config::pki(
  Stdlib::Absolutepath           $app_pki_ca   = "${::libreswan::app_pki_dir}/pki/cacerts/cacerts.pem",
  Stdlib::Absolutepath           $app_pki_cert = "${::libreswan::app_pki_dir}/pki/public/${::fqdn}.pub",
  Optional[Stdlib::Absolutepath] $app_pki_key  = "${::libreswan::app_pki_dir}/pki/private/${::fqdn}.pem"
){

  libreswan::nss::init_db { "NSSDB ${::libreswan::ipsecdir}":
    dbdir       => $::libreswan::ipsecdir,
    password    => $::libreswan::nssdb_password,
    nsspassword => $::libreswan::nsspassword,
    token       => $::libreswan::token,
    fips        => $::libreswan::fips,
    require     => File['/etc/ipsec.conf'],
  }


  file { $::libreswan::app_pki_dir :
    ensure =>  directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0640'
  }

  if $::libreswan::pki {
    ::pki::copy { $::libreswan::app_pki_dir :
      source  => $::libreswan::app_pki_external_source,
      pki     => $::libreswan::pki,
      require => File[$::libreswan::app_pki_dir]
    }
  }
  else {
    file { "${::libreswan::app_pki_dir}/pki":
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0640'
    }
    # Do the users a favor and ensure these files so we can notify the nss database
    # when they change (see config/pki/nsspki.pp)
    file { [
       $app_pki_cert,
       $app_pki_key,
       $app_pki_ca
     ] :
       ensure =>  file,
       owner  => 'root',
       group  => 'root',
       mode   => '0700'
   }
  }
}

