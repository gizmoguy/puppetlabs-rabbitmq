require 'spec_helper_system'

describe "rabbitmq class with create_cert_user" do
  context 'should run successfully' do
    pp="
    class { '::rabbitmq':
      port              => '5672',
      create_cert_user  => true,
    }
    "

    context puppet_apply(pp) do
      its(:stderr) { should be_empty }
      its(:exit_code) { should_not == 1 }
      its(:refresh) { should be_nil }
      its(:stderr) { should be_empty }
      its(:exit_code) { should be_zero }
    end
  end

  context 'service_ensure => stopped:' do
    pp = "class { 'rabbitmq': service_ensure => stopped }"

    context puppet_apply(pp) do
      its(:stderr) { should be_empty }
      its(:exit_code) { should_not == 1 }
      its(:refresh) { should be_nil }
      its(:stderr) { should be_empty }
      its(:exit_code) { should be_zero }
    end
  end

  context 'service_ensure => running:' do
    pp = "class { 'rabbitmq': service_ensure => running }"

    context puppet_apply(pp) do |r|
      its(:stderr) { should be_empty }
      its(:exit_code) { should_not == 1 }
      its(:refresh) { should be_nil }
      its(:stderr) { should be_empty }
      its(:exit_code) { should be_zero }
    end
  end
end
