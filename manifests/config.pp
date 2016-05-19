# == Class ipsec_tunnel::config
#
# This class is called from ipsec_tunnel for service config.
#
class ipsec_tunnel::config {
  assert_private()

# set up the /etc/ipsec.conf file and any directories that
# might be defined in it.
  file { '/etc/ipsec.conf':
    ensure  => file,
    owner   => root,
    mode    => '0400',
    notify  =>  Service['ipsec'],
    content => template('ipsec_tunnel/etc/ipsec.conf.erb')
  }
  file { $::ipsec_tunnel::secretsfile:
    ensure => file,
    owner  => root,
    mode   => '0400',
  }
  file { $::ipsec_tunnel::dumpdir:
    ensure => directory,
    owner  => root,
    mode   => '0700',
  }
  if $::ipsec_tunnel::plutostderrlog {
    file {$::ipsec_tunnel::plutostderrlog:
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
  ipsec_tunnel::nss::init_db { "NSSDB ${::ipsec_tunnel::ipsecdir}":
    dbdir        =>  $::ipsec_tunnel::ipsecdir,
    password     =>  $::ipsec_tunnel::nssdb_password,
    init_command =>  '/sbin/ipsec initnss',
    require      =>  File['/etc/ipsec.conf'],
    notify       => Class['::ipsec_tunnel::nsspki']
  }
}
