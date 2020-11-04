# Valid virtual private addresses
type Libreswan::VirtualPrivate = Array[
  Variant[
    Libreswan::IP::V4::VirtualPrivate,
    Libreswan::IP::V6::VirtualPrivate
  ]
]
