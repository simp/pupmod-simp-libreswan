class libreswan::opportunistic {

# Connections for Opportunistic Encryption

  libreswan::connection{ 'clear':
    type   =>  'passthrough',
    authby =>  'never',
    left   =>  '%defaultroute',
    right  =>  '%group',
    auto   =>  'ondemand'
  }
  libreswan::connection{ 'clear-or-private':
    type             =>  'tunnel',
    left             =>  '%defaultroute',
    leftid           =>  '%fromcert',
    right            =>  '%opportunisticgroup',
    rightid          =>  '%fromcert',
    rightca          =>  '%same',
    leftauth         =>  'rsasig',
    rightauth        =>  'rsasig',
    ikev2            =>  'insist',
    narrowing        =>  'yes',
    negotiationshunt =>  'passthrough',
    failureshunt     =>  'passthrough',
    rekey            =>  'no',
    auto             =>  'ondemand'
  }
  libreswan::connection{ 'private-or-clear':
    type             =>  'tunnel',
    left             =>  '%defaultroute',
    leftid           =>  '%fromcert',
    right            =>  '%opportunisticgroup',
    rightid          =>  '%fromcert',
    rightca          =>  '%same',
    leftauth         =>  'rsasig',
    rightauth        =>  'rsasig',
    ikev2            =>  'insist',
    narrowing        =>  'yes',
    negotiationshunt =>  'passthrough',
    failureshunt     =>  'passthrough',
    rekey            =>  'no',
    auto             =>  'ondemand'
  }
  libreswan::connection{ 'private':
    type             =>  'tunnel',
    left             =>  '%defaultroute',
    leftid           =>  '%fromcert',
    right            =>  '%opportunisticgroup',
    rightid          =>  '%fromcert',
    rightca          =>  '%same',
    leftauth         =>  'rsasig',
    rightauth        =>  'rsasig',
    ikev2            =>  'insist',
    narrowing        =>  'yes',
    negotiationshunt =>  'hold',
    failureshunt     =>  'reject',
    rekey            =>  'no',
    auto             =>  'ondemand'
  }
  libreswan::connection{ 'block':
    type   =>  'reject',
    authby =>  'never',
    left   =>  '%defaultroute',
    right  =>  '%group',
    auto   =>  'ondemand'
  }
}
