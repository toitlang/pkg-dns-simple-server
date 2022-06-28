// Copyright (C) 2022 Toitware ApS.
// Use of this source code is governed by a Zero-Clause BSD license that can
// be found in the EXAMPLES_LICENSE file.

import net
import net.wifi
import net.udp
import reader show BufferedReader

import simple_dns_server show SimpleDns

main:
  network := wifi.establish --ssid="mywifi" --password="12345678"

  task:: run_dns network

  server_socket := network.tcp_listen 80
  while true:
    socket := server_socket.accept
    if not socket: continue
    print "Got a connection attempt on port 80 from $socket.peer_address"
    reader := BufferedReader socket
    while line := reader.read_line:
      if line.ends_with "\r": line = line[..line.size - 1]
      print "HTTP header: $line"
      if line == "": break
    try:
      socket.write "HTTP/1.1 200 OK\r\n"
      socket.write "text/plain\r\n"
      socket.write "Content-Type: text/plain\r\n"
      socket.write "\r\n"
      socket.write "Welcome to Toit! $(Time.now)\r\n"
    finally:
      socket.close
  server_socket.close
  network.close


run_dns network/net.Interface:
  my_ip := network.address

  socket := network.udp_open --port=53

  hosts := SimpleDns my_ip  // Answer my IP to all queries.

  while true:
    datagram /udp.Datagram := socket.receive
    response := hosts.lookup datagram.data
    if response:
      error := response[3] & 0xf
      socket.send
          udp.Datagram response datagram.address
