/* Copyright (c) 2018-2019 Rubicon Communications, LLC (Netgate)
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"fmt"
	"log"
	"net"
)

// startServer is a very simplistic UDP server that listens on the specified port and passes received messages
// to a parser, without regard for where they came from. In production, it would be better to set up a rx channel
// for each source
func startServer(port string) {

	host := ":" + port
	proto := "udp"

	if verbose {
		fmt.Printf("Starting server %s %s\n", proto, host)
	}

	log.Printf("tnsrids version %s started. Listening on UDP  %s", version, host)

	// Start a listener
	listener, error := net.ListenPacket(proto, host)
	if error != nil {
		log.Fatal("Unable to start UDP listener")
		return
	}

	defer listener.Close()

	// channel acts like a FIFO providing a 4096 string buffer between reading hosts via UDP and updating TNSR via RESTCONF
	hf := make(chan string, 4096)

	// Start the go routine that reads from the channel and processes the syslog messages
	go processHosts(hf)

	// Read incoming syslog messages and push them into the FIFO
	for {
		message := make([]byte, 4096)
		length, _, err := listener.ReadFrom(message)
		if err != nil {
			log.Fatal("Unable to read from UDP listener")
			return
		}

		if length > 0 {
			parseAlerts(string(message[0:length]), hf)
		}
	}
}
