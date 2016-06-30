# This class configures the ipsec.conf file and creates
# any directories needed by this file that are not already there.
#
class libreswan::config {
  assert_private()

  # set up the /etc/ipsec.conf file and any directories that
  # might be defined in it.
  # have to copy variables local because scope and scope.lookup don't work
  # in if statements.
  $myid                = $::libreswan::myid
  $interfaces          = $::libreswan::interfaces
  $listen              = $::libreswan::listen
  $keep_alive          = $::libreswan::keep_alive
  $myvendorid          = $::libreswan::myvendorid
  $nhelpers            = $::libreswan::nhelpers
  $plutofork           = $::libreswan::plutofork
  $crlcheckinterval    = $::libreswan::crlcheckinterval
  $strictcrlpolicy     = $::libreswan::strictcrlpolicy
  $syslog              = $::libreswan::syslog
  $uniqueids           = $::libreswan::uniqueids
  $plutorestartoncrash = $::libreswan::plutorestartoncrash
  $plutostderrlog      = $::libreswan::plutostderrlog
  $plutostderrlogtime  = $::libreswan::plutostderrlogtime
  $force_busy          = $::libreswan::force_busy
  $statsbin            = $::libreswan::statsbin
  $perpeerlog          = $::libreswan::perpeerlog
  $fragicmp            = $::libreswan::fragicmp
  $hidetos             = $::libreswan::hidetos
  $overridemtu         = $::libreswan::overridemtu

  file { '/etc/ipsec.conf':
    ensure  => file,
    owner   => root,
    mode    => '0400',
    notify  => Service['ipsec'],
    content => template('libreswan/etc/ipsec.conf.erb')
  }
  file { $::libreswan::dumpdir:
    ensure => directory,
    owner  => root,
    mode   => '0700',
    before => File['/etc/ipsec.conf']
  }
  if $::libreswan::plutostderrlog {
    file {$::libreswan::plutostderrlog:
      ensure => file,
      owner  => root,
      mode   => '0600',
      before => File['/etc/ipsec.conf']
    }
  }
}
