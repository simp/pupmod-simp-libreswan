# == Class ipsec::config
#
# This class is called from ipsec for service config.
#
class ipsec::config {
  assert_private()

# set up the /etc/ipsec.conf file and any directories that
# might be defined in it.
  file { '/etc/ipsec.conf':
    ensure  => file,
    owner   => root,
    mode    => '0400',
    notify  =>  Service['ipsec'],
    content => template('ipsec/etc/ipsec.conf.erb')
  }
  file { $::ipsec::secretsfile:
    ensure => file,
    owner  => root,
    mode   => '0400',
  }
  file { $::ipsec::dumpdir:
    ensure => directory,
    owner  => root,
    mode   => '0700',
  }
  if $::ipsec::plutostderrlog {
    file {$::ipsec::plutostderrlog:
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
  ipsec::nss::init_db { "NSSDB ${::ipsec::ipsecdir}":
    dbdir        =>  $::ipsec::ipsecdir,
    password     =>  $::ipsec::nssdb_password,
    init_command =>  '/sbin/ipsec initnss',
    require      =>  File['/etc/ipsec.conf'],
    notify       => Class['::ipsec::nsspki']
  }
}
