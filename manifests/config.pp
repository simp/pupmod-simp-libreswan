# == Class libreswan::config
#
# This class is called from ipsec for service config.
#
class libreswan::config {
  assert_private()

# set up the /etc/ipsec.conf file and any directories that
# might be defined in it.
# have to copy variables local because scope and scope.lookup don't work
# in if statements.
  $myid = $::libreswan::myid
  $interfaces = $::libreswan::interfaces
  $listen =  $::libreswan::listen
  $keep_alive = $::libreswan::keep_alive
  $myvendorid = $::libreswan::myvendorid
  $nhelpers =  $::libreswan::nhelpers
  $plutofork =  $::libreswan::plutofork
  $crlcheckinterval = $::libreswan::crlcheckinterval
  $strictcrlpolicy = $::libreswan::strictcrlpolicy
  $syslog = $::libreswan::syslog
  $uniqueids = $::libreswan::uniqueids
  $plutorestartoncrash = $::libreswan::plutorestartoncrash
  $plutostderrlog = $::libreswan::plutostderrlog
  $plutostderrlogtime = $::libreswan::plutostderrlogtime
  $force_busy =  $::libreswan::force_busy
  $statsbin = $::libreswan::statsbin
  $perpeerlog = $::libreswan::perpeerlog
  $fragicmp = $::libreswan::fragicmp
  $hidetos = $::libreswan::hidetos
  $overridemtu = $::libreswan::overridemtu

  file { '/etc/ipsec.conf':
    ensure  => file,
    owner   => root,
    mode    => '0400',
    notify  =>  Service['ipsec'],
    content => template('libreswan/etc/ipsec.conf.erb')
  }
  file { $::libreswan::secretsfile:
    ensure  => file,
    owner   => root,
    mode    => '0400',
    content => ": RSA \"${::fqdn}\"",
  }
  file { $::libreswan::dumpdir:
    ensure => directory,
    owner  => root,
    mode   => '0700',
  }
  if $::libreswan::plutostderrlog {
    file {$::libreswan::plutostderrlog:
      ensure => file,
      owner  => root,
      mode   => '0600',
    }
  }
# Create the database using IPSEC.  The ipsec command needs the
# ipsec.conf file to be configured to get information on where to
# create the database.
# init_db checks if the *.db files exist in the dbdir and does
# nothing if they do.  So make sure your ipsecdir is clean when you start.
  libreswan::nss::init_db { "NSSDB ${::libreswan::ipsecdir}":
    dbdir        =>  $::libreswan::ipsecdir,
    password     =>  $::libreswan::nssdb_password,
    nsspassword  =>  $::libreswan::nsspassword,
    token        =>  $::libreswan::token,
    use_fips     =>  $::libreswan::use_fips,
    init_command =>  '/sbin/ipsec initnss',
    require      =>  File['/etc/ipsec.conf'],
    notify       => Class['::libreswan::nsspki']
  }
}
