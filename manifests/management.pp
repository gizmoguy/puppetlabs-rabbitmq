#
class rabbitmq::management {

  $create_cert_user  = $rabbitmq::create_cert_user
  $delete_guest_user = $rabbitmq::delete_guest_user
  $user_list         = $rabbitmq::user_list

  define rabbitmq_user_with_full_permissions {
    rabbitmq_user { $name:
      ensure   => present,
      password => $name,
      provider => 'rabbitmqctl',
    }
    rabbitmq_user_permissions { "${name}@/":
      configure_permission => '.*',
      read_permission      => '.*',
      write_permission     => '.*',
    }
  }

  if $delete_guest_user {
    rabbitmq_user{ 'guest':
      ensure   => absent,
      provider => 'rabbitmqctl',
    }
  }

  rabbitmq_user_with_full_permissions { $user_list: }

  if $create_cert_user {
    rabbitmq_user_with_full_permissions { $::clientcert: }
  } else {
    rabbitmq_user { $::clientcert:
      ensure   => absent,
      provider => 'rabbitmqctl',
    }
  }

}
