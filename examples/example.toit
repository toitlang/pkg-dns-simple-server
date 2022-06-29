// Copyright (C) 2022 Toitware ApS.
// Use of this source code is governed by a Zero-Clause BSD license that can
// be found in the EXAMPLES_LICENSE file.

import net
import net.udp as net_udp
import net.modules.udp

import dns_simple_server show SimpleDns

main:
  socket := udp.Socket "0.0.0.0" 5353

  hosts := SimpleDns (net.IpAddress.parse "1.2.3.4")
  hosts.add_host "fives" (net.IpAddress.parse "5.5.5.5")
  hosts.add_host "sixes.com" (net.IpAddress.parse "6.6.6.6")

  while true:
    datagram /net_udp.Datagram := socket.receive
    response := hosts.lookup datagram.data
    if response:
      socket.send
          net_udp.Datagram response datagram.address
