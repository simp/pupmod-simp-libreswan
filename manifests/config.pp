# @summary Configures `ipsec.conf` and necessary directories.
#
class libreswan::config {
  assert_private()

  $myid                = $libreswan::myid
  $protostack          = $libreswan::protostack
  $interfaces          = $libreswan::interfaces
  $listen              = $libreswan::listen
  $nflog_all           = $libreswan::nflog_all
  $keep_alive          = $libreswan::keep_alive
  $virtual_private     = $libreswan::virtual_private
  $myvendorid          = $libreswan::myvendorid
  $nhelpers            = $libreswan::nhelpers
  $plutofork           = $libreswan::plutofork
  $crlcheckinterval    = $libreswan::crlcheckinterval
  $strictcrlpolicy     = $libreswan::strictcrlpolicy
  $ocsp_enable         = $libreswan::ocsp_enable
  $ocsp_strict         = $libreswan::ocsp_strict
  $ocsp_timeout        = $libreswan::ocsp_timeout
  $ocsp_uri            = $libreswan::ocsp_uri
  $ocsp_trustname      = $libreswan::ocsp_trustname
  $syslog              = $libreswan::syslog
  $plutodebug          = $libreswan::plutodebug
  $uniqueids           = $libreswan::uniqueids
  $plutorestartoncrash = $libreswan::plutorestartoncrash
  $logfile             = $libreswan::logfile
  $logappend           = $libreswan::logappend
  $logtime             = $libreswan::logtime
  $ddos_mode           = $libreswan::ddos_mode
  $ddos_ike_treshold   = $libreswan::ddos_ike_treshold
  $dumpdir             = $libreswan::dumpdir
  $statsbin            = $libreswan::statsbin
  $ipsecdir            = $libreswan::ipsecdir
  $secretsfile         = $libreswan::secretsfile
  $fragicmp            = $libreswan::fragicmp
  $hidetos             = $libreswan::hidetos
  $overridemtu         = $libreswan::overridemtu
  $block_cidrs         = $libreswan::block_cidrs
  $clear_cidrs         = $libreswan::clear_cidrs
  $clear_private_cidrs = $libreswan::clear_private_cidrs
  $private_cidrs       = $libreswan::private_cidrs
  $private_clear_cidrs = $libreswan::private_clear_cidrs

  file { '/etc/ipsec.conf':
    ensure  => file,
    owner   => root,
    mode    => '0400',
    notify  => Class['libreswan::service'],
    content => template('libreswan/etc/ipsec.conf.erb')
  }
  file { $libreswan::dumpdir:
    ensure => directory,
    owner  => root,
    mode   => '0700',
    before => File['/etc/ipsec.conf']
  }
  file { "${ipsecdir}/policies/block":
    ensure  => 'file',
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => template('libreswan/etc/ipsec.d/policies/block.erb'),
  }
  file { "${ipsecdir}/policies/clear":
    ensure  => 'file',
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => template('libreswan/etc/ipsec.d/policies/clear.erb'),
  }
  file { "${ipsecdir}/policies/clear-or-private":
    ensure  => 'file',
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => template('libreswan/etc/ipsec.d/policies/clear_or_private.erb'),
  }
  file { "${ipsecdir}/policies/private":
    ensure  => 'file',
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => template('libreswan/etc/ipsec.d/policies/private.erb'),
  }
  file { "${ipsecdir}/policies/private-or-clear":
    ensure  => 'file',
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => template('libreswan/etc/ipsec.d/policies/private_or_clear.erb'),
  }
  if $libreswan::logfile {
    file { $libreswan::logfile:
      ensure => file,
      owner  => root,
      mode   => '0600',
      before => File['/etc/ipsec.conf']
    }
  }
}
