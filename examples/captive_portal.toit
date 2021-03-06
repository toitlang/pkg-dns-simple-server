// Copyright (C) 2022 Toitware ApS.
// Use of this source code is governed by a Zero-Clause BSD license that can
// be found in the EXAMPLES_LICENSE file.

// An example of a Soft AP program that can run on the ESP32 to generate a
// captive portal website that phones can connect to.  Uses techniques
// similar to hotel WiFis to get the phone to pop up a page to interact
// with an ESP32 that has no actual connectivity to the Internet.

import http
import net
import net.wifi
import net.udp
import reader show BufferedReader

import dns_simple_server show SimpleDnsServer

import .website.resources

// Name of the WiFi hotspot that the device advertizes.  You can
// have a random name here to avoid clashes, eg.
// "captive_portal_$(random 1_000_000_000)".
CAPTIVE_PORTAL_SSID     ::= "mywifi"
CAPTIVE_PORTAL_PASSWORD ::= "12345678"

// On the device we use port 80 for the web server, but that is not
// available to non-privileged users on desktop systems, so we fall
// back on this port when testing on desktop Toit.
HOST_PORT ::= 8080

// Customize this function to insert dynamic content in files using the
// {{variable}} syntax.
look_up_variable variable/string -> string:
  if variable == "time":
    return Time.now.local.stringify

  // Default - just color it red to make it easy for the developer to spot.
  return "<font color=red>{{$variable}}</font>"

TEMPORARY_REDIRECTS ::= {
  "generate_204": "/",    // Used by Android captive portal detection.
  "gen_204": "/",         // Used by Android captive portal detection.
  // Add more redirects in order to create an alias for a file.
}

// If you add files to the website directory you may need to add any missing
// file extensions here.  Use only lower case.
MIME_TYPES ::= {
  "txt":  "text/plain",
  "html": "text/html",
  "css":  "text/css",
  "png":  "image/png",
  "pdf":  "application/pdf",
  "jpg":  "image/jpeg",
  "jpeg": "image/jpeg",
  "ico":  "image/png",
  "svg":  "image/svg+xml",
}

main:
  network := null
  on_device := false
  exception := catch --trace:
    network = wifi.establish --ssid=CAPTIVE_PORTAL_SSID --password=CAPTIVE_PORTAL_PASSWORD
    on_device = true
  if exception:
    network = net.open

  if on_device:
    task:: run_dns network

  port := on_device ? 80 : HOST_PORT
  server := http.Server
  print "Listening on http://localhost:$port/"

  server.listen network port:: | request writer |
    handle request writer

mime_type path/string -> string:
  suffix := path
  index := path.index_of --last "."
  if index != -1:
    suffix = path[index + 1..]
  return MIME_TYPES.get suffix --if_absent=:
    suffix = to_lower_case suffix
    return MIME_TYPES.get suffix --if_absent=:
      throw "Unknown MIME type for $path"

to_lower_case in/string -> string:
  in.do:
    if 'A' <= it <= 'Z':
      ba := in.to_byte_array
      ba.size.repeat:
        if 'A' <= ba[it] <= 'Z':
          ba[it] |= 0x20
      return ba.to_string
  return in

substitute_variables result/string -> string:
  parts := []
  while result != "":
    index := result.index_of "{{"
    if index == -1:
      parts.add result
      break
    parts.add result[..index]
    substitution_size := result[index..].index_of "}}"
    variable := result[index + 2..index + substitution_size].trim
    result = result[index + substitution_size + 2..]
    parts.add
      look_up_variable variable
  return parts.join ""

handle request/http.Request writer/http.ResponseWriter -> none:
  path := request.path
  if path == "/": path = "index.html"
  if path.starts_with "/": path = path[1..]

  TEMPORARY_REDIRECTS.get path --if_present=:
    writer.headers.set "Location" it
    writer.write_headers 302
    return

  result := RESOURCE_MAP.get path --if_absent=:
    writer.headers.set "Content-Type" "text/plain"
    writer.write_headers 404
    writer.write "Not found: $path"
    return
  if result is string and (result.index_of "{{") != -1:
    result = substitute_variables result
  writer.headers.set "Content-Type" (mime_type path)
  writer.write result

run_dns network/net.Interface:
  my_ip := network.address

  socket := network.udp_open --port=53

  hosts := SimpleDnsServer my_ip  // Answer my IP to all queries.

  while true:
    datagram /udp.Datagram := socket.receive
    response := hosts.lookup datagram.data
    if response:
      socket.send
          udp.Datagram response datagram.address
