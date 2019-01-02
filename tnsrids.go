// Package provides a bridge bwtween Snort hand the TNSR ACL syste./ Snort alert messages are reveived either via
// a TCP socket on localhost, or a Unix socket. The alerts are parsed and used to create RESTCONF calls to TNSR
// which manipulate the ACL

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
	"github.com/robfig/cron"
	"gopkg.in/natefinch/lumberjack.v2" // Log writer/rotator
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
)

func main() {
	var err error

	// Setup logging
	log.SetOutput(&lumberjack.Logger{
		Filename:   dfltLogpath, // Log file path
		MaxSize:    1,           // megabytes
		MaxBackups: 10,
		MaxAge:     28, // days
	})

	// Set up the options/arguments parser
	// Create a configuration structure
	var tconfig Config

	// Tell it what options and arguments to look for
	//					name, cmd line arg, string vs bool, help text
	tconfig.addOption("verbose", "v", false, "Output log messages to the console", "no")
	tconfig.addOption("show", "show", false, "List the current block rules and exit", "no")
	tconfig.addOption("reap", "reap", false, "Delete block rules older than <config> minutes and exit", "no")
	tconfig.addOption("host", "h", true, "Host name of TNSR instance (including protocol prefix", dfltHost)
	tconfig.addOption("port", "p", true, "UDP port on which to listen for alert messages", dfltPort)
	tconfig.addOption("capath", "ca", true, "TLS certificate authority file path", dfltCA)
	tconfig.addOption("certpath", "cert", true, "TLS certificate file path", dfltCert)
	tconfig.addOption("keypath", "key", true, "TLS key file path", dfltKey)
	tconfig.addOption("maxage", "m", true, "Maximum age of rules before deletion. 0 = never delete", dfltMaxage)

	// Now process the command line & config file into a map of options and values
	options := tconfig.read()

	if options["help"] == "yes" {
		tconfig.printUsage("tnsrids usage:")
		return
	}

	// Update the global vars
	if options["verbose"] == "yes" {
		verbose = true
	}

	tnsrhost = options["host"]
	maxruleage, _ = strconv.ParseUint(options["maxage"], 10, 64)
	maxruleage *= 60 // Convert to seconds
	port := options["port"]

	// Attempt to initilize TLS
	useTLS = false

	if strings.HasPrefix(tnsrhost, "https://") {
		err = TLSSetup(options["capath"], options["certpath"], options["keypath"])
		if err != nil {
			if verbose {
				fmt.Println(err)
			}

			log.Fatal(err)
		}
	}

	// Just list the installed ACL rules and quit
	if options["show"] == "yes" {
		showACLs()
		return
	}

	// Just delete the old ACL rules and quit
	if options["reap"] == "yes" {
		err := reapACLs()
		if err != nil {
			fmt.Printf("ERROR: Failed to reap old rule: %v\n", err)
		}

		return
	}

	// Set up a timer for regular tasks if maxruleage > 0
	tnsrCron := cron.New()
	if maxruleage > 0 {
		// Such as reaping old rules
		tnsrCron.AddFunc(reapPeriod, func() { reapACLs() })
		tnsrCron.Start()
	}

	// Prepare a handler to catch terminating signals (^C etc)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		if verbose {
			fmt.Println("Cleaning up and exiting")
		}

		// Close the cron process
		if maxruleage > 0 {
			tnsrCron.Stop()
		}

		os.Exit(2)
	}()

	// Clean out any old rules
	err = reapACLs()
	if err != nil {
		log.Fatal("Unable to reap old rules prior to starting server")
	}

	// And finally start the UDP listener
	// This also starts a number of go routines to process Snort alerts and update the TNSR instance
	startServer(port)
}
