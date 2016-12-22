type Libreswan::ConnAddr = Variant[
                             Enum['%any','%defaultroute','%opportunistic','%opportunisticgroup','%group'],
                             Array[Simplib::IP::V4],
                             Array[Simplib::IP::V6],
                             Simplib::IP::V4,
                             Simplib::IP::V6,
                             Pattern['^%\w+']
                          ]
