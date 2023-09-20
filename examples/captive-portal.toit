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

import dns-simple-server show SimpleDnsServer

import .website.resources

// Name of the WiFi hotspot that the device advertizes.  You can
// have a random name here to avoid clashes, eg.
// "captive_portal_$(random 1_000_000_000)".
CAPTIVE-PORTAL-SSID     ::= "mywifi"
CAPTIVE-PORTAL-PASSWORD ::= "12345678"

// On the device we use port 80 for the web server, but that is not
// available to non-privileged users on desktop systems, so we fall
// back on this port when testing on desktop Toit.
HOST-PORT ::= 8080

// Customize this function to insert dynamic content in files using the
// {{variable}} syntax.
look-up-variable variable/string -> string:
  if variable == "time":
    return Time.now.local.stringify

  // Default - just color it red to make it easy for the developer to spot.
  return "<font color=red>{{$variable}}</font>"

TEMPORARY-REDIRECTS ::= {
  "generate_204": "/",    // Used by Android captive portal detection.
  "gen_204": "/",         // Used by Android captive portal detection.
  // Add more redirects in order to create an alias for a file.
}

// If you add files to the website directory you may need to add any missing
// file extensions here.  Use only lower case.
MIME-TYPES ::= {
  "txt":  "text/plain",
  "html": "text/html",
  "css":  "text/css",
  "png":  "image/png",
  "webp": "image/webp",
  "pdf":  "application/pdf",
  "jpg":  "image/jpeg",
  "jpeg": "image/jpeg",
  "ico":  "image/png",
  "svg":  "image/svg+xml",
}

main:
  network := null
  on-device := false
  exception := catch --trace:
    network = wifi.establish --ssid=CAPTIVE-PORTAL-SSID --password=CAPTIVE-PORTAL-PASSWORD
    on-device = true
  if exception:
    network = net.open

  if on-device:
    task:: run-dns network

  port := on-device ? 80 : HOST-PORT
  server := http.Server
  print "Listening on http://localhost:$port/"

  server.listen network port:: | request writer |
    handle request writer

mime-type path/string -> string:
  suffix := path
  if suffix.ends-with ".gz":
    suffix = suffix[..suffix.size - 3]
  index := suffix.index-of --last "."
  if index != -1:
    suffix = suffix[index + 1..]
  return MIME-TYPES.get suffix --if-absent=:
    suffix = suffix.to-ascii-lower
    return MIME-TYPES.get suffix --if-absent=:
      throw "Unknown MIME type for $path"

compression-type path/string -> string?:
  if path.ends-with ".gz":
    return "gzip"
  return null

handle request/http.Request writer/http.ResponseWriter -> none:
  path := request.path
  if path == "/": path = "index.html"
  if path == "/hotspot-detect.html": path = "index.html"  // Needed for iPhones.
  if path.starts-with "/": path = path[1..]

  TEMPORARY-REDIRECTS.get path --if-present=:
    writer.headers.set "Location" it
    writer.write-headers 302
    return

  result := RESOURCE-MAP.get path --if-absent=:
    writer.headers.set "Content-Type" "text/plain"
    writer.write-headers 404
    writer.write "Not found: $path"
    return
  if result is string:
    result = result.substitute: look-up-variable it
  writer.headers.set "Content-Type" (mime-type path)
  if compression-type path:
    writer.headers.set "Content-Encoding" (compression-type path)

  writer.write result

run-dns network/net.Interface:
  my-ip := network.address

  socket := network.udp-open --port=53

  hosts := SimpleDnsServer my-ip  // Answer my IP to all queries.

  while true:
    datagram /udp.Datagram := socket.receive
    response := hosts.lookup datagram.data
    if response:
      socket.send
          udp.Datagram response datagram.address
