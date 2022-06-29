// Copyright (C) 2022 Toitware ApS.
// Use of this source code is governed by a Zero-Clause BSD license that can
// be found in the tests/TESTS_LICENSE file.

import expect show *
import net.modules.dns
import net

import dns_simple_server show SimpleDnsServer

main:
  test_lookup_failure
  test_default_lookup
  test_hosts_lookup
  test_case_lookup

expect_lookup_failure reply/ByteArray name/string id/int -> none:
  // Server should echo back the query ID.
  expect_equals #[id >> 8, id & 0xff] reply[..2]

  // The reply bit should be set on the reply.
  expect_equals 0x80 reply[2] & 0x80

  // Server should return a name error because foo.com lookup failed.
  expect_equals dns.ERROR_NAME reply[3] & 0xf

  // Server should echo back the domain that was looked up.
  expect_equals name
      dns.decode_name reply 12: null

expect_lookup_success reply/ByteArray name/string id/int address/net.IpAddress -> none:
  // Server should echo back the query ID.
  expect_equals #[id >> 8, id & 0xff] reply[..2]

  // The reply bit should be set on the reply.
  expect_equals 0x80 reply[2] & 0x80

  // Server should return no error because foo.com lookup succeeded.
  expect_equals dns.ERROR_NONE reply[3] & 0xf

  // Server should echo back the domain that was looked up.
  expect_equals name
      dns.decode_name reply 12: null

  // Packet ends with the IP address.
  expect_equals address.raw reply[reply.size - 4..]

test_lookup_failure:
  no_default := SimpleDnsServer

  query := dns.create_query "foo.com" 0x1234

  // Look up a name that is not in the hosts table.
  reply := no_default.lookup query

  expect_lookup_failure reply "foo.com" 0x1234

test_default_lookup:
  HOST ::= "foo.com"
  ADDRESS ::= net.IpAddress.parse "192.168.3.4"
  ID ::= 0x1234

  server := SimpleDnsServer ADDRESS

  query := dns.create_query HOST ID

  // Lookup a name that returns the default IP.
  reply := server.lookup query

  expect_lookup_success reply HOST ID ADDRESS

test_hosts_lookup:
  HEST ::= "www.simply-the-hest.dk"
  ID ::= 0x99fd
  ADDRESS ::= net.IpAddress.parse "10.45.44.43"

  server := SimpleDnsServer
  server.add_host HEST ADDRESS

  query := dns.create_query HEST ID

  // Lookup a name that is in the hosts table.
  reply := server.lookup query

  expect_lookup_success reply HEST ID ADDRESS

test_case_lookup:
  HoSt ::= "www.sVaMpE-BoB.us"
  HOST ::= "www.svampe-bob.us"
  ID ::= 0x4200 + 103
  ADDRESS ::= net.IpAddress.parse "142.250.74.164"

  server := SimpleDnsServer
  server.add_host HoSt ADDRESS

  query := dns.create_query HOST ID

  // Lookup a name that is in the hosts table, but in a different case.
  reply := server.lookup query

  expect_lookup_success reply HOST ID ADDRESS

  server = SimpleDnsServer
  server.add_host HOST ADDRESS

  query = dns.create_query HoSt ID

  // Lookup a name with the wrong case.
  reply = server.lookup query

  // We expect the case we used in the query to be reflected in the reply.
  expect_lookup_success reply HoSt ID ADDRESS
