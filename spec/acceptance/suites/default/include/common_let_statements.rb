shared_context 'shared let', :shared_context => :metadata do
  let(:manifest) { "class { 'libreswan': }"}

  let(:left) { only_host_with_role( hosts, "left#{os_major_version}" ) }
  let(:right) { only_host_with_role( hosts, "right#{os_major_version}" ) }

  let(:leftinterface) { get_private_network_interface(left) }
  let(:leftip) { fact_on(left, %(ipaddress_#{leftinterface})) }
  let(:leftfqdn) { fact_on( left, 'fqdn' ) }
  let(:rightinterface) { get_private_network_interface(right) }
  let(:rightip) { fact_on(right, %(ipaddress_#{rightinterface})) }
  let(:rightfqdn) { fact_on( right, 'fqdn' ) }
  let(:nc_port) { 2389 }

  let(:leftconnection) { <<~EOS
      libreswan::connection{ 'default':
        leftcert      => "${::fqdn}",
        left          => "#{leftip}",
        leftrsasigkey => '%cert',
        leftsendcert  => 'always',
        authby        => 'rsasig',
      }
      libreswan::connection{ 'outgoing' :
        right          => "#{rightip}",
        rightrsasigkey => '%cert',
        auto           => 'start'
      }
  EOS
  }
  let(:rightconnection) { <<~EOS
      libreswan::connection{ 'default':
        leftcert      => "${::fqdn}",
        left          => "#{rightip}",
        leftrsasigkey => '%cert',
        leftsendcert  => 'always',
        authby        => 'rsasig'
      }
      libreswan::connection{ 'outgoing' :
        right          => "#{leftip}",
        rightrsasigkey => '%cert',
        auto           => 'start'
      }
    EOS
  }
  let(:hieradata_left) { <<~EOS
    ---
    libreswan::service_name : 'ipsec'
    libreswan::interfaces : ["ipsec0=#{leftip}"]
    libreswan::listen : '#{leftip}'
    simp_options::pki: true
    simp_options::pki::source: '/etc/pki/simp-testing/pki'
  EOS
  }

  let(:hieradata_right){ <<~EOM
    ---
    libreswan::service_name : 'ipsec'
    libreswan::interfaces : ["ipsec0=#{rightip}"]
    libreswan::listen : '#{rightip}'
    simp_options::pki: true
    simp_options::pki::source: '/etc/pki/simp-testing/pki'
  EOM
  }

  let(:testfile) { "/tmp/testfile.#{Time.now.to_i}" }

  let(:nc) { # we want the full path so we can pkill intelligently
    if os_major_version == '6'
      '/usr/bin/nc'
    else
      '/bin/nc'
    end
  }
end
