#
class rabbitmq::management {

  $create_cert_user  = $rabbitmq::create_cert_user
  $delete_guest_user = $rabbitmq::delete_guest_user

  if $delete_guest_user {
    rabbitmq_user{ 'guest':
      ensure   => absent,
      provider => 'rabbitmqctl',
    }
  }

  if $create_cert_user {
    rabbitmq_user { $::clientcert:
      ensure   => present,
      password => $::clientcert,
      provider => 'rabbitmqctl',
    }
  } else {
    rabbitmq_user { $::clientcert:
      ensure   => absent,
      provider => 'rabbitmqctl',
    }
  }

}
