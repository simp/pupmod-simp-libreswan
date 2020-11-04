# Valid libreswan interfaces
type Libreswan::Interfaces = Array[
  Variant[
    Enum['%none','%defaultroute'],
    Pattern['(\w+=\w+)']
  ]
]
