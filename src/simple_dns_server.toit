// Copyright (C) 2022 Toitware ApS. All rights reserved.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

import binary show BIG_ENDIAN
import bytes show Buffer
import net.modules.udp
import net
import net.modules.dns

/**
A very simple DNS server.
The server can respond to A record queries for IPv4.
There is a static map of domain names to IP addresses, and an
  optional default value that is returned for any other queries.
It should be enough for a captive portal.
*/
class SimpleDns:
  hosts_ := {:}
  default /net.IpAddress?

  constructor .default=null:

  add_host name/string ip/net.IpAddress -> none:
    hosts_[name] = ip

  /**
  Takes a DNS query in the form of a UDP packet in RFC 1035 format, and
    constructs a response packet.
  Never throws, but may log stack traces for very broken packets.
  Returns an error packet to return to the client, or null for very broken
    input packets.
  */
  lookup query/ByteArray -> ByteArray?:
    exception := catch --trace:
      if query.size < 4:
        print "size only $query.size"
        return null  // Not enough data to construct an error packet.
      query_id := BIG_ENDIAN.uint16 query 0
      response := ResponseBuilder_ query_id --recursion=(query[2] & 1 != 0)

      if query.size < 12:
        print "too small $query.size"
        return response.create_error_ dns.FORMAT_ERROR

      // Check for expected query, but mask out the recursion desired bit.
      if query[2] & ~1 != 0x00:
        print "query[2] = $(%02x query[2])"
        return response.create_error_ dns.FORMAT_ERROR
      error := query[3] & 0xf
      if error != 0:
        print "Error is $error"
        return response.create_error_ dns.FORMAT_ERROR
      queries := BIG_ENDIAN.uint16 query 4
      answers := BIG_ENDIAN.uint16 query 6
      name_servers := BIG_ENDIAN.uint16 query 8
      additional := BIG_ENDIAN.uint16 query 10
      if answers != 0 or name_servers != 0:
        print "answers=$answers name_servers=$name_servers"
        return response.create_error_ dns.FORMAT_ERROR
      position := 12

      queries.repeat:
        q_name := dns.decode_name query position: position = it
        q_type := BIG_ENDIAN.uint16 query position
        q_class := BIG_ENDIAN.uint16 query position + 2
        position += 4

        if q_class == dns.INTERNET_CLASS and q_type == dns.A_RECORD:
          print "Got query for $q_name"
          if hosts_.contains q_name:
            response.resource_record q_name --address=hosts_[q_name]
          else if default:
            response.resource_record q_name --address=default
          else:
            return response.create_error_ dns.NAME_ERROR
        else:
          return response.create_error_ dns.NOT_IMPLEMENTED
      additional.repeat:
        a_name := dns.decode_name query position: position = it
        a_type := BIG_ENDIAN.uint16 query position
        a_class := BIG_ENDIAN.uint16 query position + 2
        a_ttl := BIG_ENDIAN.uint32 query position + 4
        a_length := BIG_ENDIAN.uint16 query position + 8
        position += 10 + a_length
        // Currently we don't do anything with the optional data.
        // We might want to recognize type 41, which is OPT, and allows
        // the max UDP size of the sender to be recorded.  RFC 2671.
      return response.get
    return null

class ResponseBuilder_:
  substring_cache := {:}
  packet /Buffer := Buffer
  resource_records_ := 0
  answer_count_offset_ := 0

  constructor query_id/int --recursion/bool:
    packet.write_int16_big_endian query_id
    bits_0 := 0b1000_0100  // Authoritative answer.
    bits_1 := 0b0000_0000  // No error.
    if recursion:
      bits_0 |= 0b0000_0001
      bits_1 |= 0b1000_0000
    packet.write_byte bits_0
    packet.write_byte bits_1
    packet.write_int16_big_endian 0  // Query count.
    answer_count_offset_ = packet.size
    packet.write_int16_big_endian 0  // Answer count.
    packet.write_int16_big_endian 0  // Name server count.
    packet.write_int16_big_endian 0  // Additional information count.

  write_domain_ name/string:
    while true:
      if name == ".": name = ""
      if substring_cache.contains name:
        // Point to name we already emitted once.
        packet.write_int16_big_endian 0b1100_0000_0000_0000 | substring_cache[name]
        return
      else:
        if name == "":
          packet.write_byte 0
          return
        // Register the current position in the packet in the cache of suffixes.
        substring_cache[name] = packet.size
        dot := name.index_of "."
        if dot != -1:
          prefix := name[..dot]
          packet.write_byte prefix.size
          packet.write prefix
          name = name[dot + 1..]
        else:
          packet.write_byte name.size
          packet.write name
          name = ""

  resource_record -> none
      name/string
      --address /net.IpAddress
      --r_type /int = dns.A_RECORD
      --r_class /int = dns.INTERNET_CLASS
      --ttl /int=30:
    write_domain_ name
    packet.write_int16_big_endian r_type
    packet.write_int16_big_endian r_class
    packet.write_int32_big_endian ttl
    packet.write_int16_big_endian 4  // Size of IP address
    packet.write address.to_byte_array
    resource_records_++

  get -> ByteArray:
    result := packet.bytes
    BIG_ENDIAN.put_int16 result answer_count_offset_ resource_records_
    return result

  create_error_ error_code/int -> ByteArray:
    print "Create error $error_code"
    result := get
    result[3] |= error_code
    return result
