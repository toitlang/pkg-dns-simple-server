// Copyright (C) 2022 Toitware ApS. All rights reserved.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

import binary show BIG_ENDIAN
import bytes show Buffer
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
  Known domain names can be added with $add_host.
  Domain names that are not known, and where the default answer should not be
    given, can be set with $remove_host.
  */
  constructor .default=null:

  /// Adds a mapping from hostname to IP address.
  add_host name/string ip/net.IpAddress -> none:
    hosts_[to_lower_case_ name] = ip

  /**
  Removes a mapping from hostname to IP address.
  The given name will cause an error response to a DNS query, even if a
    default answer was given in the constructor.
  */
  remove_host name/string -> none:
    hosts_[to_lower_case_ name] = null

  /**
  Takes a DNS query in the form of a UDP packet in RFC 1035 format, and
    constructs a response packet.
  Never throws, but may log stack traces for very broken packets.
  Returns an error packet to return to the client, or null for very broken
    input packets.
  */
  lookup query/ByteArray -> ByteArray?:
    exception := catch --trace:
      if query.size < 4: return null  // Not enough data to construct an error packet.
      query_id := BIG_ENDIAN.uint16 query 0
      response := ResponseBuilder_ query_id --recursion=(query[2] & 1 != 0)

      if query.size < 12: return response.create_error_ dns.ERROR_FORMAT

      // Check for expected query, but mask out the recursion desired bit.
      if query[2] & ~1 != 0x00: return response.create_error_ dns.ERROR_FORMAT
      error := query[3] & 0xf
      if error != 0: return null  // Don't respond to errors.
      queries := BIG_ENDIAN.uint16 query 4
      answers := BIG_ENDIAN.uint16 query 6
      name_servers := BIG_ENDIAN.uint16 query 8
      additional := BIG_ENDIAN.uint16 query 10
      if answers != 0 or name_servers != 0:
        return response.create_error_ dns.ERROR_FORMAT
      position := 12

      // Repeat the queries in the response packet.
      queries.repeat:
        q_name := dns.decode_name query position: position = it
        q_type := BIG_ENDIAN.uint16 query position
        q_class := BIG_ENDIAN.uint16 query position + 2
        position += 4
        if q_class == dns.CLASS_INTERNET and q_type == dns.RECORD_A:
          response.resource_record q_name
        else:
          return response.create_error_ dns.ERROR_NOT_IMPLEMENTED

      // Reread the query packet.
      position = 12

      // Write the answers.
      queries.repeat:
        q_name := dns.decode_name query position: position = it
        q_type := BIG_ENDIAN.uint16 query position
        q_class := BIG_ENDIAN.uint16 query position + 2
        position += 4

        response_address := hosts_.get q_name --if_absent=:
          if hosts_.size != 0:
            lower_case_name := to_lower_case_ q_name
            hosts_.get lower_case_name --if_absent=: default
          else:
            default

        if response_address == null:
          return response.create_error_ dns.ERROR_NAME

        response.resource_record q_name --address=response_address

      additional.repeat:
        a_name := dns.decode_name query position: position = it
        a_type := BIG_ENDIAN.uint16 query position
        a_class := BIG_ENDIAN.uint16 query position + 2
        a_ttl := BIG_ENDIAN.uint32 query position + 4
        a_length := BIG_ENDIAN.uint16 query position + 8
        position += 10 + a_length
        // Currently we don't do anything with the additional data.
        // We might want to recognize type 41, which is OPT, and allows
        // the max UDP size of the sender to be recorded.  RFC 2671.

      return response.get

    // If we caught and traced an exception we return null - no response is
    // sent to the client.
    return null

class ResponseBuilder_:
  substring_cache_ ::= {:}
  packet /Buffer := Buffer
  resource_records_ := 0
  static QUERY_COUNT_OFFSET_ ::= 4
  static ANSWER_COUNT_OFFSET_ ::= 6

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
    packet.write_int16_big_endian 0  // Answer count.
    packet.write_int16_big_endian 0  // Name server count.
    packet.write_int16_big_endian 0  // Additional information count.

  write_domain_ name/string:
    while true:
      if name == ".": name = ""
      if substring_cache_.contains name:
        // Point to name we already emitted once.
        packet.write_int16_big_endian 0b1100_0000_0000_0000 | substring_cache_[name]
        return
      else:
        if name == "":
          packet.write_byte 0
          return
        // Register the current position in the packet in the cache of suffixes.
        substring_cache_[name] = packet.size
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
      name /string
      --address /net.IpAddress? = null
      --r_type /int = dns.RECORD_A
      --r_class /int = dns.CLASS_INTERNET
      --ttl /int=30:
    write_domain_ name
    packet.write_int16_big_endian r_type
    packet.write_int16_big_endian r_class
    if address:
      // In the query section we just repeat the query, but in the answer
      // section we have the following extra fields.
      packet.write_int32_big_endian ttl
      packet.write_int16_big_endian 4  // Size of IP address
      packet.write address.to_byte_array
      resource_records_++

  get -> ByteArray:
    result := packet.bytes
    BIG_ENDIAN.put_int16 result QUERY_COUNT_OFFSET_ resource_records_
    BIG_ENDIAN.put_int16 result ANSWER_COUNT_OFFSET_ resource_records_
    return result

  create_error_ error_code/int -> ByteArray:
    result := get
    result[3] |= error_code
    return result

to_lower_case_ in/string -> string:
  in.do: | char |
    if 'A' <= char <= 'Z':
      byte_array := in.to_byte_array
      byte_array.size.repeat:
        if 'A' <= byte_array[it] <= 'Z':
          byte_array[it] |= 0x20
      return byte_array.to_string
  return in
