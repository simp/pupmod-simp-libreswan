# == Class ipsec_tunnel::nss::init_db
#  This class initializes the NSS database, sets the correct password and
#  makes sure FIPS is configured according to use_fips.
# # [*dbdir*]
#   Type: Absolute Path
#   Default: +/etc/ipsec+
#   Directroy where the nss db will be created.
#
# [*password*]
#   Type: String
#   Default: +empty+
#   Password used to protect the database. Each NSS database is broken up into
#   tokens used for different types of certificates, Smart cards, FIPS compliant,
#   non FIPD.  This util sets the FIPS and non fips token to they same password.
#   The tokens are defined by $::ipsec_tunnel::nsstoken.  You can add  tokens to
#   array if there are other parts of the database you want to protect.
#
# [*destroyexisting*]
#   Type: Boolean
#   Default: +false+
#   If true, it will remove the existing database before runniing the init command.
#
# [*init_command*]
#   Type: String
#   Default: +"/sbin/ipsec initnss"+
#   This is the command that will be executed to initialize the database.  It defaults
#   to the ipsec command installed by libreswan.  Libre Swan does not explain, what if anything
#   it does differently or in addition the NSS commands (modutil, certutil)
define ipsec_tunnel::nss::init_db(
  $dbdir,
  $password,
  $destroyexisting = false,
  $init_command = '/sbin/ipsec initnss',
  $use_fips = $::ipsec_tunnel::use_fips,
  $token = $::ipsec_tunnel::token
){

  validate_absolute_path($dbdir)
  validate_bool($destroyexisting)
  validate_string($password)
# Because this is an initialization, the current password should be none.
  $oldpassword = 'none'
  $dbfile = "${dbdir}/cert9.db"

  if $destroyexisting {
    exec { "Remove NSS database ${dbdir}":
      onlyif  => "test -f ${dbfile}",
      command => "rm -f ${dbdir}/*.db",
      path    => ['/bin', '/sbin'],
      before  => Exec["init_nssdb ${dbdir}"],
    }
  }

  exec { "init_nssdb ${dbdir}":
    creates => $dbfile,
    before  => File["${dbdir}/nsspassword"],
    command => $init_command,
    path    => ['/bin', '/sbin'],
    notify  => Exec["update token password ${dbdir}"]
  }

  file {"${dbdir}/nsspassword":
    ensure  => file,
    mode    => '0600',
    owner   => root,
    content => "${::ipsec_tunnel::token}:${password}\n",
    notify  => Exec["update token password ${dbdir}"]
  }

#Run scripts to set password.
  exec { "update token password ${dbdir}":
    command     => "/usr/local/scripts/nss/update_nssdb_password.sh ${dbdir} ${password} ${oldpassword} \"${token}\"",
    path        => ['/bin','/sbin'],
    refreshonly => true,
  }

#Make sure FIPS is set according to use_fips.
  if $use_fips {
    exec { "nssdb in fips mode ${dbdir}":
      command => "modutil -dbdir sql:${dbdir} -fips true",
      onlyif  =>  "modutil -dbdir sql:${dbdir} -chkfips false",
      path    => ['/bin', '/sbin'],
      require => Exec["init_nssdb ${dbdir}"]
    }
  } else {
    exec { "make sure nssdb not in fips mode ${dbdir}":
      command => "modutil  -dbdir sql:${dbdir} -fips false",
      onlyif  => "modutil -dbdir sql:${dbdir} -chkfips true",
      path    => ['/bin', '/sbin'],
      require => Exec["init_nssdb ${dbdir}"]
    }
  }
}
