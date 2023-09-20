// Copyright (C) 2022 Toitware ApS.
// Use of this source code is governed by a Zero-Clause BSD license that can
// be found in the tests/TESTS_LICENSE file.

import expect show *
import net.modules.dns
import net

import dns-simple-server show SimpleDnsServer

main:
  test-lookup-failure
  test-default-lookup
  test-hosts-lookup
  test-case-lookup

expect-lookup-failure reply/ByteArray name/string id/int -> none:
  // Server should echo back the query ID.
  expect-equals #[id >> 8, id & 0xff] reply[..2]

  // The reply bit should be set on the reply.
  expect-equals 0x80 reply[2] & 0x80

  // Server should return a name error because foo.com lookup failed.
  expect-equals dns.ERROR-NAME reply[3] & 0xf

  // Server should echo back the domain that was looked up.
  expect-equals name
      dns.decode-name reply 12: null

expect-lookup-success reply/ByteArray name/string id/int address/net.IpAddress -> none:
  // Server should echo back the query ID.
  expect-equals #[id >> 8, id & 0xff] reply[..2]

  // The reply bit should be set on the reply.
  expect-equals 0x80 reply[2] & 0x80

  // Server should return no error because foo.com lookup succeeded.
  expect-equals dns.ERROR-NONE reply[3] & 0xf

  // Server should echo back the domain that was looked up.
  expect-equals name
      dns.decode-name reply 12: null

  // Packet ends with the IP address.
  expect-equals address.raw reply[reply.size - 4..]

test-lookup-failure:
  no-default := SimpleDnsServer

  query := dns.create-query_ "foo.com" 0x1234 dns.RECORD-A

  // Look up a name that is not in the hosts table.
  reply := no-default.lookup query

  expect-lookup-failure reply "foo.com" 0x1234

  // Now do a similar test with a DNS server that does not always respond with
  // the default answer.
  DEFAULT ::= net.IpAddress.parse "10.0.0.42"
  ADDRESS ::= net.IpAddress.parse "192.168.0.2"
  EXPLICIT-HOST ::= "www.zero.two.com"
  has-default := SimpleDnsServer DEFAULT

  has-default.remove-host "www.nonexistent.com"
  has-default.add-host EXPLICIT-HOST ADDRESS
  has-default.add-host "foo.com" ADDRESS
  has-default.remove-host "foo.com"

  query = dns.create-query_ "www.nonexistent.com" 0x123 dns.RECORD-A
  reply = has-default.lookup query
  expect-lookup-failure reply "www.nonexistent.com" 0x123

  query = dns.create-query_ EXPLICIT-HOST 0x5552 dns.RECORD-A
  reply = has-default.lookup query
  expect-lookup-success reply EXPLICIT-HOST 0x5552 ADDRESS

  query = dns.create-query_ "foo.com" 0x5553 dns.RECORD-A
  reply = has-default.lookup query
  expect-lookup-failure reply "foo.com" 0x5553

  query = dns.create-query_ "anything.info" 0x5556 dns.RECORD-A
  reply = has-default.lookup query
  expect-lookup-success reply "anything.info" 0x5556 DEFAULT

test-default-lookup:
  HOST ::= "foo.com"
  ADDRESS ::= net.IpAddress.parse "192.168.3.4"
  ID ::= 0x1234

  server := SimpleDnsServer ADDRESS

  query := dns.create-query_ HOST ID dns.RECORD-A

  // Lookup a name that returns the default IP.
  reply := server.lookup query

  expect-lookup-success reply HOST ID ADDRESS

test-hosts-lookup:
  HEST ::= "www.simply-the-hest.dk"
  ID ::= 0x99fd
  ADDRESS ::= net.IpAddress.parse "10.45.44.43"

  server := SimpleDnsServer
  server.add-host HEST ADDRESS

  query := dns.create-query_ HEST ID dns.RECORD-A

  // Lookup a name that is in the hosts table.
  reply := server.lookup query

  expect-lookup-success reply HEST ID ADDRESS

test-case-lookup:
  HoSt ::= "www.sVaMpE-BoB.us"
  HOST ::= "www.svampe-bob.us"
  ID ::= 0x4200 + 103
  ADDRESS ::= net.IpAddress.parse "142.250.74.164"

  server := SimpleDnsServer
  server.add-host HoSt ADDRESS

  query := dns.create-query_ HOST ID dns.RECORD-A

  // Lookup a name that is in the hosts table, but in a different case.
  reply := server.lookup query

  expect-lookup-success reply HOST ID ADDRESS

  server = SimpleDnsServer
  server.add-host HOST ADDRESS

  query = dns.create-query_ HoSt ID dns.RECORD-A

  // Lookup a name with the wrong case.
  reply = server.lookup query

  // We expect the case we used in the query to be reflected in the reply.
  expect-lookup-success reply HoSt ID ADDRESS
