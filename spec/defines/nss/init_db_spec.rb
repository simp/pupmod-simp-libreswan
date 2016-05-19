require 'spec_helper'
describe 'ipsec_tunnel::nss::init_db', :type => :define do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end
        let(:common_params) { { :password => 'mypassword', :init_command => '/sbin/ipsec init_nssdb' } }
        describe "destroy existing database" do
          let(:pre_condition) { 'class { "ipsec_tunnel": use_fips => true, }' }
          let(:title  ){ 'IPSEC NSS DB' }
          let(:params) { common_params.merge(:destroyexisting => true, :dbdir => '/etc/ipsec.p') }
          it { is_expected.to contain_exec("init_nssdb #{params[:dbdir]}").with({
            :creates => "#{params[:dbdir]}/cert9.db",
            :before  => "File[#{params[:dbdir]}/nsspassword]",
            :command => "#{params[:init_command]}",
            :notify  => "Exec[update token password #{params[:dbdir]}]"
            })
          }
          it { is_expected.to contain_exec("Remove NSS database #{params[:dbdir]}").with({
            :command => "rm -f #{params[:dbdir]}/*.db",
            :onlyif  => "test -f #{params[:dbdir]}/cert9.db",
            :before  => "Exec[init_nssdb #{params[:dbdir]}]"
            })
          }
        end

        describe "dont destroy existing database" do
          let(:params) { common_params.merge(:destroyexisting => false , :dbdir => '/etc/ipsec.f') }
          let(:title  ){ 'IPSEC NSS DB' }
          it { is_expected.to_not contain_exec("Remove NSS database #{params[:dbdir]}") }
          it { is_expected.to contain_exec("init_nssdb #{params[:dbdir]}").with({
            :creates => "#{params[:dbdir]}/cert9.db",
            :before  => "File[#{params[:dbdir]}/nsspassword]",
            :command => "#{params[:init_command]}",
            :notify  => "Exec[update token password #{params[:dbdir]}]"
            })
          }
        end
        describe "ipsec_tunnel class with fips disabled" do
          let(:pre_condition) { 'class { "ipsec_tunnel": use_fips => false, }' }
          let(:params) { common_params.merge(:destroyexisting => false , :dbdir => '/etc/ipsec.g') }
          let(:title  ){ 'IPSEC NSS DB' }
          it { is_expected.to contain_exec("make sure nssdb not in fips mode #{params[:dbdir]}").with({
            :command => "modutil  -dbdir sql:#{params[:dbdir]} -fips false",
            :require => "Exec[init_nssdb #{params[:dbdir]}]"
            })
          }
          it { is_expected.to create_file("#{params[:dbdir]}/nsspassword").with({
            :content => "NSS Certificate DB:#{params[:password]}\n",
            :mode    => '0600',
            :owner   => 'root',
            :notify  => "Exec[update token password #{params[:dbdir]}]"
            })
          }
          it { is_expected.to contain_exec("update token password #{params[:dbdir]}").with({
            :command => "/usr/local/scripts/nss/update_nssdb_password.sh #{params[:dbdir]} #{params[:password]} none \"NSS Certificate DB\"",
            :refreshonly => true
            })
          }
        end

        describe "ipsec_tunnel class with fips enabled" do
          let(:pre_condition) { 'class { "ipsec_tunnel": use_fips => true, }' }
          let(:params) { common_params.merge(:destroyexisting => false , :dbdir => '/etc/ipsec.t') }
          let(:title  ){ 'IPSEC NSS DB' }
          it { is_expected.to contain_exec("nssdb in fips mode #{params[:dbdir]}").with({
            :command => "modutil -dbdir sql:#{params[:dbdir]} -fips true",
            :require => "Exec[init_nssdb #{params[:dbdir]}]"
            })
          }
          it { is_expected.to create_file("#{params[:dbdir]}/nsspassword").with({
            :content => "NSS FIPS 140-2 Certificate DB:#{params[:password]}\n",
            :mode    => '0600',
            :owner   => 'root',
            :notify  => "Exec[update token password #{params[:dbdir]}]"
            })
          }
          it { is_expected.to contain_exec("update token password #{params[:dbdir]}").with({
            :command => "/usr/local/scripts/nss/update_nssdb_password.sh #{params[:dbdir]} #{params[:password]} none \"NSS FIPS 140-2 Certificate DB\"",
            :refreshonly => true
            })
          }
        end
      end
    end
  end
end
