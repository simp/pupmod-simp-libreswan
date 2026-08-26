# @summary Manage individual fields in `/etc/ipsec.conf` and the policy files in `$ipsecdir/policies`.
#
# This class does NOT overwrite `/etc/ipsec.conf` or the policy files. It edits
# `/etc/ipsec.conf` in place using `file_line`, and only when a corresponding
# class parameter is non-undef. A bare `include libreswan` declares no
# resources here.
#
# The `config setup` section header is expected to already exist in the
# package-provided `/etc/ipsec.conf`. Each managed field is set as a
# `<key> = <value>` line; `file_line` matches and replaces an existing line
# with the same key, or inserts a new line immediately after the
# `config setup` header. New lines must NOT simply be appended: the stock
# `/etc/ipsec.conf` ends with `include /etc/ipsec.d/*.conf`, and libreswan
# rejects parameter lines that appear after a top-level `include` with a
# syntax error.
#
# To remove fields or policy files, use `libreswan::purge_settings` and
# `libreswan::purge_policies` respectively.
#
class libreswan::config {
  assert_private()

  $ipsec_conf = '/etc/ipsec.conf'

  $_settings = {
    'myid'                => $libreswan::myid,
    'listen'              => $libreswan::listen,
    'nflog-all'           => $libreswan::nflog_all,
    'keep-alive'          => $libreswan::keep_alive,
    'myvendorid'          => $libreswan::myvendorid,
    'nhelpers'            => $libreswan::nhelpers,
    'plutofork'           => $libreswan::plutofork,
    'crlcheckinterval'    => $libreswan::crlcheckinterval,
    'strictcrlpolicy'     => $libreswan::strictcrlpolicy,
    'ocsp-enable'         => $libreswan::ocsp_enable,
    'ocsp-strict'         => $libreswan::ocsp_strict,
    'ocsp-timeout'        => $libreswan::ocsp_timeout,
    'ocsp-uri'            => $libreswan::ocsp_uri,
    'ocsp-trustname'      => $libreswan::ocsp_trustname,
    'syslog'              => $libreswan::syslog,
    'plutodebug'          => $libreswan::plutodebug,
    'uniqueids'           => $libreswan::uniqueids,
    'plutorestartoncrash' => $libreswan::plutorestartoncrash,
    'logfile'             => $libreswan::logfile,
    'logappend'           => $libreswan::logappend,
    'logtime'             => $libreswan::logtime,
    'ddos-mode'           => $libreswan::ddos_mode,
    'ddos-ike-treshold'   => $libreswan::ddos_ike_treshold,
    'dumpdir'             => $libreswan::dumpdir,
    'protostack'          => $libreswan::protostack,
    'fragicmp'            => $libreswan::fragicmp,
    'hidetos'             => $libreswan::hidetos,
    'overridemtu'         => $libreswan::overridemtu,
    'interfaces'          => $libreswan::interfaces ? {
      Undef   => undef,
      default => "\"${join($libreswan::interfaces, ' ')}\"",
    },
    'virtual-private'     => $libreswan::virtual_private ? {
      Undef   => undef,
      default => join($libreswan::virtual_private, ','),
    },
    'statsbin'            => $libreswan::statsbin ? {
      Undef   => undef,
      default => "\"${libreswan::statsbin}\"",
    },
  }

  $_managed_keys = $_settings.filter |$_, $v| { $v =~ NotUndef }.keys
  $_setting_conflicts = $libreswan::purge_settings.filter |$k| { $k in $_managed_keys }
  unless $_setting_conflicts.empty {
    fail("libreswan: keys cannot appear in both managed settings and \$purge_settings: ${_setting_conflicts.join(', ')}")
  }

  unless $_managed_keys.empty {
    # Guarantee the anchor for inserted lines. Without it, file_line would
    # append new settings after the trailing top-level `include`, which
    # libreswan rejects with a syntax error. If the header itself is missing
    # from a hand-edited file, this appends one at end of file — libreswan
    # parses that as an additional `config setup` section and merges it.
    file_line { "libreswan ${ipsec_conf} config setup header":
      path  => $ipsec_conf,
      line  => 'config setup',
      match => '^config setup\s*$',
    }
  }

  $_settings.each |String $key, $value| {
    if $value =~ NotUndef {
      libreswan::config::setting { $key:
        path    => $ipsec_conf,
        value   => $value,
        after   => '^config setup\s*$',
        require => File_line["libreswan ${ipsec_conf} config setup header"],
      }
    }
  }

  $libreswan::purge_settings.each |String $key| {
    libreswan::config::setting { "purge-${key}":
      ensure => 'absent',
      key    => $key,
      path   => $ipsec_conf,
    }
  }

  $_policies = {
    'block'            => $libreswan::block_cidrs,
    'clear'            => $libreswan::clear_cidrs,
    'clear-or-private' => $libreswan::clear_private_cidrs,
    'private'          => $libreswan::private_cidrs,
    'private-or-clear' => $libreswan::private_clear_cidrs,
  }

  $_managed_policies = $_policies.filter |$_, $v| { $v =~ NotUndef }.keys
  $_policy_conflicts = $libreswan::purge_policies.filter |$p| { $p in $_managed_policies }
  unless $_policy_conflicts.empty {
    fail("libreswan: names cannot appear in both managed policies and \$purge_policies: ${_policy_conflicts.join(', ')}")
  }

  if $_managed_policies.size > 0 or $libreswan::purge_policies.size > 0 {
    ensure_resource('file', "${libreswan::ipsecdir}/policies", { 'ensure' => 'directory' })
  }

  $_policies.each |String $policy, $cidrs| {
    if $cidrs =~ NotUndef {
      file { "${libreswan::ipsecdir}/policies/${policy}":
        ensure  => 'file',
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
        content => "${join($cidrs, "\n")}\n",
      }
    }
  }

  $libreswan::purge_policies.each |String $policy| {
    file { "${libreswan::ipsecdir}/policies/${policy}":
      ensure => 'absent',
    }
  }

  if $libreswan::manage_file_permissions {
    # Restore the pre-5.0.0 ownership/mode management. Content is still
    # handled by the file_line resources above (which autorequire this file).
    file { $ipsec_conf:
      ensure => 'file',
      owner  => 'root',
      mode   => '0400',
    }

    file { $libreswan::ipsecdir:
      ensure => 'directory',
      owner  => 'root',
      mode   => '0700',
    }

    if $libreswan::dumpdir =~ NotUndef {
      file { $libreswan::dumpdir:
        ensure => 'directory',
        owner  => 'root',
        mode   => '0700',
      }
    }
  }
}
