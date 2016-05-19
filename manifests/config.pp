# == Class libreswan::config
#
# This class is called from ipsec for service config.
#
class libreswan::config {
  assert_private()

# set up the /etc/ipsec.conf file and any directories that
# might be defined in it.
  file { '/etc/ipsec.conf':
    ensure  => file,
    owner   => root,
    mode    => '0400',
    notify  =>  Service['ipsec'],
    content => template('libreswan/etc/ipsec.conf.erb')
  }
  file { $::libreswan::secretsfile:
    ensure => file,
    owner  => root,
    mode   => '0400',
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
    init_command =>  '/sbin/ipsec initnss',
    require      =>  File['/etc/ipsec.conf'],
    notify       => Class['::libreswan::nsspki']
  }
}
