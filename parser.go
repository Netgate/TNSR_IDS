// parser.go extracts the host we need to block from a Snort alert message and puts it onto channel
// The Go routine processHosts() reads the hosts from the channel and updates the ACL

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
	//	"fmt"
	"regexp"
	//	"time"
)

// Go routine to continuously reads host names channel and pass them to the ACL updater
func processHosts(hf <-chan string) {
	for {
		addRule(<-hf, true)
	}
}

// Extract the first IPv4 address from a string
func findIP(input string) string {
	numBlock := "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
	regexPattern := numBlock + "\\." + numBlock + "\\." + numBlock + "\\." + numBlock

	regEx := regexp.MustCompile(regexPattern)
	return regEx.FindString(input)
}

// parseAlerts processes incoming syslog records and pushes the host to block into a channel read by peocessHosts
func parseAlerts(alert string, hf chan<- string) {
	addr := findIP(alert)
	hf <- addr + "/32"
}
