// Copyright (C) 2022 Toitware ApS. All rights reserved.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

import io
import net
import net.modules.dns

/**
A very simple DNS server.
The server can respond to A record queries for IPv4.
There is a static map of domain names to IP addresses, and an
  optional default value that is returned for any other queries.
It should be enough for a captive portal.
*/
class SimpleDnsServer:
  hosts_ ::= {:}
  default /net.IpAddress?

  /**
  Creates a simple DNS server with a $lookup method.
  The $default argument, if given, is an IP address that is returned
    for all unknown domain names.
  Known domain names can be added with $add-host.
  Domain names that are not known, and where the default answer should not be
    given, can be set with $remove-host.
  */
  constructor .default=null:

  /// Adds a mapping from hostname to IP address.
  add-host name/string ip/net.IpAddress -> none:
    hosts_[to-lower-case_ name] = ip

  /**
  Removes a mapping from hostname to IP address.
  The given name will cause an error response to a DNS query, even if a
    default answer was given in the constructor.
  */
  remove-host name/string -> none:
    hosts_[to-lower-case_ name] = null

  /**
  Takes a DNS query in the form of a UDP packet in RFC 1035 format, and
    constructs a response packet.
  Never throws, but may log stack traces for very broken packets.
  Returns an error packet to return to the client, or null for very broken
    input packets.
  */
  lookup query/ByteArray -> ByteArray?:
    reader := io.Reader query
    reader-be := reader.big-endian
    exception := catch --trace:
      if reader.content-size < 4: return null  // Not enough data to construct an error packet.
      query-id := reader-be.read-uint16
      recursion-byte := reader.read-byte
      response := ResponseBuilder_ query-id --recursion=(recursion-byte & 1 != 0)

      if query.size < 12: return response.create-error_ dns.ERROR-FORMAT

      // Check for expected query, but mask out the recursion desired bit.
      if recursion-byte & ~1 != 0x00: return response.create-error_ dns.ERROR-FORMAT
      error := reader.read-byte & 0xf
      if error != 0: return null  // Don't respond to errors.
      queries := reader-be.read-uint16
      answers := reader-be.read-uint16
      name-servers := reader-be.read-uint16
      additional := reader-be.read-uint16
      if answers != 0 or name-servers != 0:
        return response.create-error_ dns.ERROR-FORMAT

      // Repeat the queries in the response packet.
      queries.repeat:
        q-name := dns.decode-name reader query
        q-type := reader-be.read-uint16
        q-class := reader-be.read-uint16
        if q-class == dns.CLASS-INTERNET and q-type == dns.RECORD-A:
          response.resource-record q-name
        else:
          return response.create-error_ dns.ERROR-NOT-IMPLEMENTED

      // Reread the query packet.
      reader = io.Reader query
      reader-be = reader.big-endian
      reader.skip 12  // Skip the header.

      // Write the answers.
      queries.repeat:
        q-name := dns.decode-name reader query
        q-type := reader-be.read-uint16
        q-class := reader-be.read-uint16

        response-address := hosts_.get q-name --if-absent=:
          if hosts_.size != 0:
            lower-case-name := to-lower-case_ q-name
            hosts_.get lower-case-name --if-absent=: default
          else:
            default

        if response-address == null:
          return response.create-error_ dns.ERROR-NAME

        response.resource-record q-name --address=response-address

      additional.repeat:
        a-name := dns.decode-name reader query
        a-type := reader-be.read-uint16
        a-class := reader-be.read-uint16
        a-ttl := reader-be.read-uint32
        a-length := reader-be.read-uint16
        reader.skip a-length
        // Currently we don't do anything with the additional data.
        // We might want to recognize type 41, which is OPT, and allows
        // the max UDP size of the sender to be recorded.  RFC 2671.

      return response.get

    // If we caught and traced an exception we return null - no response is
    // sent to the client.
    return null

class ResponseBuilder_:
  substring-cache_ ::= {:}
  packet/io.Buffer := io.Buffer
  resource-records_ := 0
  static QUERY-COUNT-OFFSET_ ::= 4
  static ANSWER-COUNT-OFFSET_ ::= 6

  constructor query-id/int --recursion/bool:
    packet-be := packet.big-endian
    packet-be.write-int16 query-id
    bits-0 := 0b1000_0100  // Authoritative answer.
    bits-1 := 0b0000_0000  // No error.
    if recursion:
      bits-0 |= 0b0000_0001
      bits-1 |= 0b1000_0000
    packet.write-byte bits-0
    packet.write-byte bits-1
    packet-be.write-int16 0  // Query count.
    packet-be.write-int16 0  // Answer count.
    packet-be.write-int16 0  // Name server count.
    packet-be.write-int16 0  // Additional information count.

  write-domain_ name/string:
    while true:
      if name == ".": name = ""
      if substring-cache_.contains name:
        // Point to name we already emitted once.
        packet.big-endian.write-int16 (0b1100_0000_0000_0000 | substring-cache_[name])
        return
      else:
        if name == "":
          packet.write-byte 0
          return
        // Register the current position in the packet in the cache of suffixes.
        substring-cache_[name] = packet.size
        dot := name.index-of "."
        if dot != -1:
          prefix := name[..dot]
          packet.write-byte prefix.size
          packet.write prefix
          name = name[dot + 1..]
        else:
          packet.write-byte name.size
          packet.write name
          name = ""

  resource-record -> none
      name /string
      --address /net.IpAddress? = null
      --r-type /int = dns.RECORD-A
      --r-class /int = dns.CLASS-INTERNET
      --ttl /int=30:
    packet-be := packet.big-endian
    write-domain_ name
    packet-be.write-int16 r-type
    packet-be.write-int16 r-class
    if address:
      // In the query section we just repeat the query, but in the answer
      // section we have the following extra fields.
      packet-be.write-int32 ttl
      packet-be.write-int16 4  // Size of IP address
      packet.write address.to-byte-array
      resource-records_++

  get -> ByteArray:
    packet-be := packet.big-endian
    packet-be.put-int16 --at=QUERY-COUNT-OFFSET_ resource-records_
    packet-be.put-int16 --at=ANSWER-COUNT-OFFSET_ resource-records_
    return packet.bytes

  create-error_ error-code/int -> ByteArray:
    result := get
    result[3] |= error-code
    return result

to-lower-case_ in/string -> string:
  in.do: | char |
    if 'A' <= char <= 'Z':
      byte-array := in.to-byte-array
      byte-array.size.repeat:
        if 'A' <= byte-array[it] <= 'Z':
          byte-array[it] |= 0x20
      return byte-array.to-string
  return in
