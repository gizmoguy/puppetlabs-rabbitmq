require 'spec_helper'

describe 'rabbitmq' do

  context 'on unsupported distributions' do
    let(:facts) {{ :osfamily => 'Unsupported' }}

    it 'we fail' do
      expect { subject }.to raise_error(/not supported on an Unsupported/)
    end
  end

  context 'on Debian' do
    let(:facts) {{ :osfamily => 'Debian', :lsbdistcodename => 'squeeze' }}
    it 'includes rabbitmq::repo::apt' do
      should contain_class('rabbitmq::repo::apt')
    end
  end

  context 'on Redhat' do
    let(:facts) {{ :osfamily => 'RedHat' }}
    it 'includes rabbitmq::repo::rhel' do
      should contain_class('rabbitmq::repo::rhel')
    end
  end
  
  ['Debian', 'RedHat', 'SUSE', 'Archlinux'].each do |distro|
    context "on #{distro}" do
      let(:facts) {{
        :osfamily => distro,
        :rabbitmq_erlang_cookie => 'EOKOWXQREETZSHFNTPEY',
        :lsbdistcodename => 'squeeze',
        :clientcert => 'foo.bar'
      }}

      it { should contain_class('rabbitmq::install') }
      it { should contain_class('rabbitmq::config') }
      it { should contain_class('rabbitmq::service') }


      context 'with admin_enable set to true' do
        let(:params) {{ :admin_enable => true }}
        context 'with service_manage set to true' do
          it 'we enable the admin interface by default' do
            should contain_class('rabbitmq::install::rabbitmqadmin')
            should contain_rabbitmq_plugin('rabbitmq_management').with(
              'require' => 'Class[Rabbitmq::Install]',
              'notify'  => 'Class[Rabbitmq::Service]'
            )
          end
        end
        context 'with service_manage set to false' do
          let(:params) {{ :admin_enable => true, :service_manage => false }}
          it 'should do nothing' do
            should_not contain_class('rabbitmq::install::rabbitmqadmin')
            should_not contain_rabbitmq_plugin('rabbitmq_management')
          end
        end
      end

      context 'with erlang_manage set to true' do
        let(:params) {{ :erlang_manage => true }}
        it 'includes erlang' do
          should contain_class('erlang')
        end
      end

      context 'with erlang_manage set to false' do
        let(:params) {{ :erlang_manage => false }}
        it 'doesnt include erlang' do
          should_not contain_class('erlang')
        end
      end


      context 'deprecated parameters' do
        describe 'cluster_disk_nodes' do
          let(:params) {{ :cluster_disk_nodes => ['node1', 'node2'] }}

          it { should contain_notify('cluster_disk_nodes') }
        end
      end

      describe 'manages configuration directory correctly' do
        it { should contain_file('/etc/rabbitmq').with(
          'ensure' => 'directory'
        )}
      end

      describe 'manages configuration file correctly' do
        it { should contain_file('rabbitmq.config') }
      end

      context 'configures config_cluster' do
        let(:facts) {{ :osfamily => distro, :rabbitmq_erlang_cookie => 'ORIGINAL' }}
        let(:params) {{
          :config_cluster           => true,
          :cluster_nodes            => ['hare-1', 'hare-2'],
          :cluster_node_type        => 'ram',
          :erlang_cookie            => 'TESTCOOKIE',
          :wipe_db_on_cookie_change => false
        }}

        describe 'with defaults' do
          it 'fails' do
            expect{subject}.to raise_error(/^ERROR: The current erlang cookie is ORIGINAL/)
          end
        end

        describe 'with wipe_db_on_cookie_change set' do
          let(:params) {{
            :config_cluster           => true,
            :cluster_nodes            => ['hare-1', 'hare-2'],
            :cluster_node_type        => 'ram',
            :erlang_cookie            => 'TESTCOOKIE',
            :wipe_db_on_cookie_change => true
          }}
          it 'wipes the database' do
            should contain_exec('wipe_db')
            should contain_file('erlang_cookie')
          end
        end

        describe 'correctly when cookies match' do
          let(:params) {{
            :config_cluster           => true,
            :cluster_nodes            => ['hare-1', 'hare-2'],
            :cluster_node_type        => 'ram',
            :erlang_cookie            => 'ORIGINAL',
            :wipe_db_on_cookie_change => true
          }}
          it 'and doesnt wipe anything' do
            should contain_file('erlang_cookie')
          end
        end

        describe 'and sets appropriate configuration' do
          let(:params) {{
            :config_cluster           => true,
            :cluster_nodes            => ['hare-1', 'hare-2'],
            :cluster_node_type        => 'ram',
            :erlang_cookie            => 'ORIGINAL',
            :wipe_db_on_cookie_change => true
          }}
          it 'for cluster_nodes' do
            should contain_file('rabbitmq.config').with({
              'content' => /cluster_nodes.*\['rabbit@hare-1', 'rabbit@hare-2'\], ram/,
            })
          end

          it 'for erlang_cookie' do
            should contain_file('erlang_cookie').with({
              'content' => 'ORIGINAL',
            })
          end
        end
      end

      describe 'rabbitmq-env configuration' do
        let(:params) {{ :environment_variables => {
          'RABBITMQ_NODE_IP_ADDRESS'    => '1.1.1.1',
          'RABBITMQ_NODE_PORT'          => '5656',
          'RABBITMQ_NODENAME'           => 'HOSTNAME',
          'RABBITMQ_SERVICENAME'        => 'RabbitMQ',
          'RABBITMQ_CONSOLE_LOG'        => 'RabbitMQ.debug',
          'RABBITMQ_CTL_ERL_ARGS'       => 'verbose',
          'RABBITMQ_SERVER_ERL_ARGS'    => 'v',
          'RABBITMQ_SERVER_START_ARGS'  => 'debug'
        }}}
        it 'should set environment variables' do
          should contain_file('rabbitmq-env.config') \
            .with_content(/RABBITMQ_NODE_IP_ADDRESS=1.1.1.1/) \
            .with_content(/RABBITMQ_NODE_PORT=5656/) \
            .with_content(/RABBITMQ_NODENAME=HOSTNAME/) \
            .with_content(/RABBITMQ_SERVICENAME=RabbitMQ/) \
            .with_content(/RABBITMQ_CONSOLE_LOG=RabbitMQ.debug/) \
            .with_content(/RABBITMQ_CTL_ERL_ARGS=verbose/) \
            .with_content(/RABBITMQ_SERVER_ERL_ARGS=v/) \
            .with_content(/RABBITMQ_SERVER_START_ARGS=debug/)
        end
      end

      context 'delete_guest_user' do
        describe 'should do nothing by default' do
          it { should_not contain_rabbitmq_user('guest') }
        end

        describe 'delete user when delete_guest_user set' do
          let(:params) {{ :delete_guest_user => true }}
          it 'removes the user' do
            should contain_rabbitmq_user('guest').with(
              'ensure'   => 'absent',
              'provider' => 'rabbitmqctl'
            )
          end
        end
      end

      context 'configuration setting' do
        describe 'stomp by default' do
          it 'should not specify stomp parameters in rabbitmq.config' do
            should_not contain_file('rabbitmq.config') \
              .with_content(/stomp/)
          end
        end
        describe 'stomp when set' do
          let(:params) {{ :config_stomp => true, :stomp_port => 5679 }}
          it 'should specify stomp port in rabbitmq.config' do
            should contain_file('rabbitmq.config') \
              .with_content(/rabbitmq_stomp/) \
              .with_content(/tcp_listeners, \[5679\]/)
          end
          it 'should install rabbitmq_stomp plugin' do
            should contain_rabbitmq_plugin('rabbitmq_stomp')
          end
        end
        describe 'stomp when set with ssl' do
          let(:params) {{ :config_stomp => true, :stomp_port => 5679, :ssl_stomp_port => 5680 }}
          it 'should specify stomp port and ssl stomp port in rabbitmq.config' do
            should contain_file('rabbitmq.config') \
              .with_content(/rabbitmq_stomp/) \
              .with_content(/tcp_listeners, \[5679\]/) \
              .with_content(/ssl_listeners, \[5680\]/)
          end
        end
      end

      context 'configuration setting' do
        describe 'shovel by default' do
          it 'should not specify shovel parameters in rabbitmq.config' do
            should_not contain_file('rabbitmq.config') \
              .with_content(/rabbitmq_shovel/)
          end
        end
        describe 'shovel when set' do
          let(:params) do
            { :config_shovel => true,
              :shovel_name => 'test_shovel',
              :shovel_exchange => 'test_exchange',
              :shovel_routing_key => 'test_key',
              :shovel_src_broker => 'testsource',
              :shovel_src_queue => 'test_src_queue',
              :shovel_dst_broker => 'testdest',
              :shovel_dst_queue => 'test_dst_queue'
            }
          end
          it 'should specify stomp port in rabbitmq.config' do
            should contain_file('rabbitmq.config') \
              .with_content(/rabbitmq_shovel/) \
              .with_content(/{test_shovel/) \
              .with_content(/{broker, "testsource"}/) \
              .with_content(/{exchange, <<"test_exchange">>}/) \
              .with_content(/{queue, <<"test_src_queue">>}/) \
              .with_content(/{routing_key, <<"test_key">>}/) \
              .with_content(/{broker, "testdest"}/) \
              .with_content(/{queue, <<"test_dst_queue">>}/)
          end
          it 'should install rabbitmq_shovel plugin' do
            should contain_rabbitmq_plugin('rabbitmq_shovel')
          end
        end
        describe 'stomp when set with ssl' do
          let(:params) {{ :config_stomp => true, :stomp_port => 5679, :ssl_stomp_port => 5680 }}
          it 'should specify stomp port and ssl stomp port in rabbitmq.config' do
            should contain_file('rabbitmq.config') \
              .with_content(/rabbitmq_stomp/) \
              .with_content(/tcp_listeners, \[5679\]/) \
              .with_content(/ssl_listeners, \[5680\]/)
          end
        end
      end

     describe 'install additional plugins' do
        let(:params) {{ :plugin_list => ['rabbitmq_shovel', 'rabbitmq_mqtt'] }}
        it 'should install rabbitmq_shovel plugin' do
          should contain_rabbitmq_plugin('rabbitmq_shovel').with({
            'ensure' => 'present'
          })
        end
        it 'should install rabbitmq_mqtt plugin' do
          should contain_rabbitmq_plugin('rabbitmq_mqtt').with({
            'ensure' => 'present'
          })
        end
      end

      describe 'configuring ldap authentication' do
        let :params do
          { :config_stomp         => true,
            :ldap_auth            => true,
            :ldap_server          => 'ldap.example.com',
            :ldap_user_dn_pattern => 'ou=users,dc=example,dc=com',
            :ldap_use_ssl         => false,
            :ldap_port            => '389',
            :ldap_log             => true
          }
        end

        it { should contain_rabbitmq_plugin('rabbitmq_auth_backend_ldap') }

        it 'should contain ldap parameters' do
          verify_contents(subject, 'rabbitmq.config', 
                          ['[', '  {rabbit, [', '    {auth_backends, [rabbit_auth_backend_internal, rabbit_auth_backend_ldap]},', '  ]}',
                            '  {rabbitmq_auth_backend_ldap, [', '    {other_bind, anon},',
                            '    {servers, ["ldap.example.com"]},',
                            '    {user_dn_pattern, "ou=users,dc=example,dc=com"},', '    {use_ssl, false},',
                            '    {port, 389},', '    {log, true}'])
        end
      end

      describe 'default_user and default_pass set' do
        let(:params) {{ :default_user => 'foo', :default_pass => 'bar' }}
        it 'should set default_user and default_pass to specified values' do
          should contain_file('rabbitmq.config') \
            .with_content(/default_user, <<"foo">>/) \
            .with_content(/default_pass, <<"bar">>/)
        end
      end

      describe 'ssl options' do
        let(:params) {
          { :ssl => true,
            :ssl_port => 3141,
            :ssl_cacert => '/path/to/cacert',
            :ssl_cert => '/path/to/cert',
            :ssl_key => '/path/to/key'
        } }

        it 'should set ssl options to specified values' do
          should contain_file('rabbitmq.config') \
            .with_content(/ssl_listeners, \[3141\]/) \
            .with_content(/ssl_options, \[{cacertfile,"\/path\/to\/cacert"/) \
            .with_content(/certfile,"\/path\/to\/cert"/) \
            .with_content(/keyfile,"\/path\/to\/key"/)
        end
      end

      describe 'ssl management options' do
        let(:params) {
          { :ssl_management => true,
            :management_port => 1337
        } }

        it 'should set ssl options to specified values' do
          should contain_file('rabbitmq.config') \
            .with_content(/listener, \[/) \
            .with_content(/{port, 1337}/) \
            .with_content(/{ssl, true}/)
        end
      end

      describe 'listen options' do
        let(:params) {
          { :ip => ["1.2.3.4", "2001::beef"],
            :port => 9999,
            :ssl => true,
            :ssl_ip => ["5.6.7.8", "2002::beef"],
            :ssl_port => 8888
        } }

        it 'should set listen options to specified values' do
          should contain_file('rabbitmq.config') \
            .with_content(/{rabbit, \[/) \
            .with_content(/tcp_listeners, \[/) \
            .with_content(/{"1.2.3.4", 9999}/) \
            .with_content(/{"2001::beef", 9999}/) \
            .with_content(/ssl_listeners, \[/) \
            .with_content(/{"5.6.7.8", 8888}/) \
            .with_content(/{"2002::beef", 8888}/)
        end
      end

      describe 'management listen options' do
        let(:params) {
          { :management_ip => "9.10.11.12",
        } }

        it 'should set management listen options to specified values' do
          should contain_file('rabbitmq.config') \
            .with_content(/{rabbitmq_management, \[/) \
            .with_content(/{ip, "9.10.11.12"}/)
        end
      end

      describe 'stomp listen options' do
        let(:params) {
          { :config_stomp => true,
            :stomp_ip => ["13.14.15.16", "2003::beef"],
            :stomp_port => 7777,
            :ssl_stomp_ip => ["17.18.19.20", "2004::beef"],
            :ssl_stomp_port => 6666
        } }

        it 'should set stomp listen options to specified values' do
          should contain_file('rabbitmq.config') \
            .with_content(/{rabbitmq_stomp, \[/) \
            .with_content(/tcp_listeners, \[/) \
            .with_content(/{"13.14.15.16", 7777}/) \
            .with_content(/{"2003::beef", 7777}/) \
            .with_content(/ssl_listeners, \[/) \
            .with_content(/{"17.18.19.20", 6666}/) \
            .with_content(/{"2004::beef", 6666}/)
        end
      end

      describe 'config_variables options' do
        let(:params) {{ :config_variables => {
            'hipe_compile'                  => true,
            'vm_memory_high_watermark'      => 0.4,
            'frame_max'                     => 131072,
            'collect_statistics'            => "none",
            'auth_mechanisms'               => "['PLAIN', 'AMQPLAIN']",
        }}}
        it 'should set environment variables' do
          should contain_file('rabbitmq.config') \
            .with_content(/\{hipe_compile, true\}/) \
            .with_content(/\{vm_memory_high_watermark, 0.4\}/) \
            .with_content(/\{frame_max, 131072\}/) \
            .with_content(/\{collect_statistics, none\}/) \
            .with_content(/\{auth_mechanisms, \['PLAIN', 'AMQPLAIN'\]\}/)
        end
      end

      context 'delete_guest_user' do
        describe 'should do nothing by default' do
          it { should_not contain_rabbitmq_user('guest') }
        end

        describe 'delete user when delete_guest_user set' do
          let(:params) {{ :delete_guest_user => true }}
          it 'removes the user' do
            should contain_rabbitmq_user('guest').with(
              'ensure'   => 'absent',
              'provider' => 'rabbitmqctl'
            )
          end
        end
      end

      context 'create_cert_user' do
        describe 'should do nothing by default' do
          it { should contain_rabbitmq_user('foo.bar').with_ensure('absent') }
        end

        describe 'create user when create_cert_user set' do
          let(:params) {{ :create_cert_user => true }}
          it 'creates the user' do
            should contain_rabbitmq_user('foo.bar').with(
              'password' => 'foo.bar',
              'ensure'   => 'present',
            )
            should contain_rabbitmq_user_permissions('foo.bar@/').with(
              'configure_permission' => '.*',
              'read_permission'   => '.*',
              'write_permission'   => '.*',
            )
          end
        end
      end

      ##
      ## rabbitmq::service
      ##
      describe 'service with default params' do
        it { should contain_service('rabbitmq-server').with(
          'ensure'     => 'running',
          'enable'     => 'true',
          'hasstatus'  => 'true',
          'hasrestart' => 'true'
        )}
      end

      describe 'service with ensure stopped' do
        let :params do
          { :service_ensure => 'stopped' }
        end

        it { should contain_service('rabbitmq-server').with(
          'ensure'    => 'stopped',
          'enable'    => false
        ) }
      end

      describe 'service with ensure neither running neither stopped' do
        let :params do
          { :service_ensure => 'foo' }
        end

        it 'should raise an error' do
          expect {
            should contain_service('rabbitmq-server').with(
              'ensure' => 'stopped' )
          }.to raise_error(Puppet::Error, /validate_re\(\): "foo" does not match "\^\(running\|stopped\)\$"/)
        end
      end

      describe 'service with manage_service equal to false' do
        let :params do
          { :service_manage => false }
        end

        it { should_not contain_service('rabbitmq-server') }
      end

    end
  end

  ##
  ## rabbitmq::install
  ##
  context "on RHEL" do
    let(:facts) {{ :osfamily => 'RedHat' }}
    let(:params) {{ :package_source => 'http://www.rabbitmq.com/releases/rabbitmq-server/v3.2.3/rabbitmq-server-3.2.3-1.noarch.rpm' }}
    it 'installs the rabbitmq package' do
      should contain_package('rabbitmq-server').with(
        'ensure'   => 'installed',
        'name'     => 'rabbitmq-server',
        'provider' => 'rpm',
        'source'   => 'http://www.rabbitmq.com/releases/rabbitmq-server/v3.2.3/rabbitmq-server-3.2.3-1.noarch.rpm'
      )
    end
  end

  context "on Debian" do
    let(:facts) {{ :osfamily => 'Debian', :lsbdistcodename => 'precise' }}
    it 'installs the rabbitmq package' do
      should contain_package('rabbitmq-server').with(
        'ensure'   => 'installed',
        'name'     => 'rabbitmq-server',
        'provider' => 'apt'
      )
    end
  end
  
  context "on Archlinux" do
    let(:facts) {{ :osfamily => 'Archlinux' }}
    it 'installs the rabbitmq package' do
      should contain_package('rabbitmq-server').with(
        'ensure'   => 'installed',
        'name'     => 'rabbitmq')
    end
  end

  describe 'repo management on Debian' do
    let(:facts)  {{ :osfamily => 'Debian' }}

    context 'with no pin' do
      let(:params) {{ :package_apt_pin => '' }}
      describe 'it sets up an apt::source' do

        it { should contain_apt__source('rabbitmq').with(
          'location'    => 'http://www.rabbitmq.com/debian/',
          'release'     => 'testing',
          'repos'       => 'main',
          'include_src' => false,
          'key'         => '056E8E56'
        ) }
      end
    end

    context 'with pin' do
      let(:params) {{ :package_apt_pin => '700' }}
      describe 'it sets up an apt::source and pin' do

        it { should contain_apt__source('rabbitmq').with(
          'location'    => 'http://www.rabbitmq.com/debian/',
          'release'     => 'testing',
          'repos'       => 'main',
          'include_src' => false,
          'key'         => '056E8E56'
        ) }

        it { should contain_apt__pin('rabbitmq').with(
          'packages' => 'rabbitmq-server',
          'priority' => '700'
        ) }

      end
    end
  end

  ['RedHat', 'SuSE'].each do |distro|
    describe "repo management on #{distro}" do
      describe 'imports the key' do
        let(:facts) {{ :osfamily => distro }}
        let(:params) {{ :package_gpg_key => 'http://www.rabbitmq.com/rabbitmq-signing-key-public.asc' }}

        it { should contain_exec("rpm --import #{params[:package_gpg_key]}").with(
          'path' => ['/bin','/usr/bin','/sbin','/usr/sbin']
        ) }
      end
    end
  end

end
