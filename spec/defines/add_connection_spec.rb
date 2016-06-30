require 'spec_helper'
describe 'libreswan::add_connection', :type => :define do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end
        let(:common_params) { { :dir => '/etc/ipsec.d', } }

        describe "create default" do
          let(:title  ){ 'default' }
          let(:params) { common_params.merge({ :left => '10.0.0.1', :leftcert => '%cert', :leftsendcert => 'always' }) }
          it { is_expected.to contain_file('%default').with({
            :notify  => 'Service[ipsec]',
            :path    => "#{params[:dir]}/#{title}.conf",
            })
          }
        end

        describe "create outgoing" do
          let(:params) { common_params.merge({ :left => '10.0.0.1', :leftcert => '%cert', :leftsendcert => 'always' }) }
          let(:title){ 'outgoing' }
          it { is_expected.to contain_file("#{title}").with({
            :notify  => 'Service[ipsec]',
            :path    => "#{params[:dir]}/#{title}.conf",
            })
          }
        end
      end
    end
  end
end
