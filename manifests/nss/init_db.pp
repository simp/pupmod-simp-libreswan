#  This class initializes the NSS database, sets the correct password, and
#  makes configures FIPS if necessary.
#
# @param dbdir [AbsolutePath] Directroy where the nss db will be created.
#
# @param password [String]
#   Password used to protect the database. Each NSS database is broken up into
#   tokens used for different types of certificates, Smart cards, FIPS compliant,
#   non FIPD. This util sets the FIPS and non fips token to they same password.
#   The tokens are defined by `$::libreswan::nsstoken`. You can add tokens to
#   array if there are other parts of the database you want to protect.
#
# @param destroyexisting [Boolean] If true, it will remove the existing database before running the init command.
#
define libreswan::nss::init_db(
  Stdlib::Absolutepath  $dbdir,
  String                $password,
  Boolean               $destroyexisting = false,
  Boolean               $fips            = simplib::lookup('simp_options::fips', { 'default_value' => false}),
  String                $token           = 'NSS Certificate DB',
  Stdlib::Absolutepath  $nsspassword     = "${dbdir}/nsspassword",
){

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

  if $::operatingsystem in ['RedHat', 'CentOS'] {
    if (versioncmp($::operatingsystemmajrelease,'7') < 0) {
      $init_command    = '/usr/sbin/ipsec initnss'
    }
    else {
      $init_command    = '/sbin/ipsec initnss'
    }
  }
  else {
    fail("Operating System '${::operatingsystem}' is not supported by ${module_name}")
  }

  exec { "init_nssdb ${dbdir}":
    creates => $dbfile,
    before  => File[$nsspassword],
    command => $init_command,
    path    => ['/bin', '/sbin'],
  }

  file { $nsspassword :
    ensure  => file,
    mode    => '0600',
    owner   => root,
    content => "${token}:${password}\n",
    notify  => Exec["update token password ${dbdir}"]
  }

  # Run scripts to set password.
  exec { "update token password ${dbdir}":
    command     => "/usr/local/scripts/nss/update_nssdb_password.sh ${dbdir} ${password} ${oldpassword} \"${token}\"",
    path        => ['/bin','/sbin'],
    refreshonly => true,
  }

  if $fips {
    exec { "nssdb in fips mode ${dbdir}":
      command => "modutil -dbdir sql:${dbdir} -fips true",
      onlyif  =>  "modutil -dbdir sql:${dbdir} -chkfips false",
      path    => ['/bin', '/sbin', '/usr/bin'],
      require => Exec["init_nssdb ${dbdir}"]
    }
  }
  else {
    exec { "make sure nssdb not in fips mode ${dbdir}":
      command => "modutil  -dbdir sql:${dbdir} -fips false",
      onlyif  => "modutil -dbdir sql:${dbdir} -chkfips true",
      path    => ['/bin', '/sbin', '/usr/bin'],
      require => Exec["init_nssdb ${dbdir}"]
    }
  }
}
