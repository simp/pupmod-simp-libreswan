type Libreswan::ConnAddr = Variant[
                             Enum['%any','%defaultroute',
                                  '%opportunistic',
                                  '%opportunisticgroup',
                                  '%group'],
                             Simplib::IP::V4,
                             Simplib::IP::V6,
                             Pattern['^%[a-zA-Z]+\d+$']
                          ]
