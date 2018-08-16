require 'spec_helper'
describe 'libreswan::nss::init_db', :type => :define do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) do
          os_facts
        end
        let(:common_params) { { :dbdir => '/etc/ipsec.d', :nsspassword => '/etc/ipsec.d/nsspassword',
          :password => 'mypassword', :token => 'NSS Certificate DB' } }
        let(:init_command) {
          if ['centos-6-x86_64','redhat-6-x86_64','oraclelinux-6-x86_64'].include?(os)
            '/usr/sbin/ipsec initnss'
          else
            '/sbin/ipsec initnss'
          end
        }
        describe 'with destroy existing database' do
          let(:title  ){ 'IPSEC NSS DB' }
          let(:params) { common_params.merge({ :destroyexisting => true }) }
          it { is_expected.to contain_exec("init_nssdb #{params[:dbdir]}").with({
            :creates => "#{params[:dbdir]}/cert9.db",
            :before  => "File[#{params[:nsspassword]}]",
            :command => init_command,
            })
          }
          it { is_expected.to contain_exec("init_nssdb #{params[:dbdir]}").with({
            :creates => "#{params[:dbdir]}/cert9.db",
            :before  => "File[#{params[:nsspassword]}]",
            :command => init_command,
            })
          }
          it { is_expected.to contain_exec("Remove NSS database #{params[:dbdir]}").with({
            :command => "rm -f #{params[:dbdir]}/*.db",
            :onlyif  => "test -f #{params[:dbdir]}/cert9.db",
            :before  => "Exec[init_nssdb #{params[:dbdir]}]"
            })
          }
        end

        describe "with don't destroy existing database" do
          let(:params) { common_params.merge( { :destroyexisting => false } ) }
          let(:title  ){ 'IPSEC NSS DB' }
          it { is_expected.to_not contain_exec("Remove NSS database #{params[:dbdir]}") }
          it { is_expected.to contain_exec("init_nssdb #{params[:dbdir]}").with({
            :creates => "#{params[:dbdir]}/cert9.db",
            :before  => "File[#{params[:nsspassword]}]",
            :command => init_command,
            })
          }
        end

        describe 'with fips=false and fips disabled' do
          let(:facts) do
            test_facts = os_facts
            test_facts[:fips_enabled] = false
            test_facts
          end
          let(:params) { common_params.merge( { :fips => false, :token => 'NSS Certificate DB'} ) }
          let(:title ){ 'IPSEC NSS DB' }
          it { is_expected.to contain_exec("make sure nssdb not in fips mode #{params[:dbdir]}").with({
            :command => "modutil  -dbdir sql:#{params[:dbdir]} -fips false",
            :require => "Exec[init_nssdb #{params[:dbdir]}]"
            })
          }
          it { is_expected.to create_file("#{params[:nsspassword]}").with({
            :content => "#{params[:token]}:#{params[:password]}\n",
            :mode    => '0600',
            :owner   => 'root',
            :notify  => "Exec[update token password #{params[:dbdir]}]"
            })
          }
          it { is_expected.to contain_exec("update token password #{params[:dbdir]}").with({
            :command => "/usr/local/scripts/nss/update_nssdb_password.sh #{params[:dbdir]} \"#{params[:password]}\" \"none\" \"#{params[:token]}\"",
            :refreshonly => true
            })
          }
        end

        describe 'ipsec class with fips=true and fips disabled' do
          let(:facts) do
            test_facts = os_facts
            test_facts[:fips_enabled] = false
            test_facts
          end
          let(:params) { common_params.merge( { :fips => true, :token => 'NSS FIPS 140-2 Certificate DB'} ) }
          let(:title  ){ 'IPSEC NSS DB' }
          it { is_expected.to contain_exec("nssdb in fips mode #{params[:dbdir]}").with({
            :command => "modutil -dbdir sql:#{params[:dbdir]} -fips true",
            :require => "Exec[init_nssdb #{params[:dbdir]}]"
            })
          }
          it { is_expected.to create_file("#{params[:nsspassword]}").with({
            :content => "#{params[:token]}:#{params[:password]}\n",
            :mode    => '0600',
            :owner   => 'root',
            :notify  => "Exec[update token password #{params[:dbdir]}]"
            })
          }
          it { is_expected.to contain_exec("update token password #{params[:dbdir]}").with({
            :command => "/usr/local/scripts/nss/update_nssdb_password.sh #{params[:dbdir]} \"#{params[:password]}\" \"none\" \"#{params[:token]}\"",
            :refreshonly => true
            })
          }
        end

        describe 'ipsec class with fips=false and fips enabled' do
          let(:facts) do
            test_facts = os_facts
            test_facts[:fips_enabled] = true
            test_facts
          end
          let(:params) { common_params.merge( { :fips => false, :token => 'NSS FIPS 140-2 Certificate DB'} ) }
          let(:title  ){ 'IPSEC NSS DB' }

          it { is_expected.to contain_exec("nssdb in fips mode #{params[:dbdir]}").with({
            :command => "modutil -dbdir sql:#{params[:dbdir]} -fips true",
            :require => "Exec[init_nssdb #{params[:dbdir]}]"
            })
          }
        end
      end
    end
  end
end
