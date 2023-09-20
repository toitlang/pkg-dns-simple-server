// Copyright (C) 2022 Toitware ApS.
// Use of this source code is governed by a Zero-Clause BSD license that can
// be found in the EXAMPLES_LICENSE file.

import net
import net.udp

import dns-simple-server show SimpleDnsServer

main:
  socket := net.open.udp-open --port=5353

  hosts := SimpleDnsServer (net.IpAddress.parse "1.2.3.4")
  hosts.add-host "fives" (net.IpAddress.parse "5.5.5.5")
  hosts.add-host "sixes.com" (net.IpAddress.parse "6.6.6.6")

  while true:
    datagram /udp.Datagram := socket.receive
    response := hosts.lookup datagram.data
    if response:
      socket.send
          udp.Datagram response datagram.address
