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

// config.go contaains all of the funtions required to process the comamnd line arguments, config file values and defaults
// This was started as an exercise to learn Go flags, methods, structures and maps, but has turned out to be useful here
// This file can be moved to its own package, or incorporated in another project as here.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

// Configuration defaults
const dfltConf string = "/etc/tnsrids/tnsrids.conf"
const dfltHost string = "https://localhost"      // Address of TNSR instance
const dfltMaxage string = "60"                   // Maximum age of rules before they are reap()-ed
const dfltPort string = "12345"                  // Default UDP port on whic alert messages are received
const dfltCA string = "/etc/tnsrids/.tls/ca.crt" // Default location of TLS ertificates
const dfltCert string = "/etc/tnsrids/.tls/tnsr.crt"
const dfltKey string = "/etc/tnsrids/.tls/tnsr.key"

// A Config is a list of configuration items that specify the option details
type Config struct {
	//	filename string
	items []ConfigItem
}

type ConfigItem struct {
	name   string // The name of this config item (used  as a map key)
	arg    string // Command line argument that sets it
	hasval bool   // Does this command line flag have an associated value string
	descr  string // Description of the item used in constructing usage/help
	dflt   string // Default value for this item
}

// Add a new config item specification to the configuration parser
func (cfg *Config) addOption(name string, arg string, hasval bool, descr string, dflt string) {
	cfg.items = append(cfg.items, ConfigItem{name, arg, hasval, descr, dflt})
}

// Print a table of options and help strings
func (cfg Config) printUsage(title string) {
	option := ""

	fmt.Println(title)
	for idx := 0; idx < len(cfg.items); idx++ {
		if len(cfg.items[idx].arg) == 0 {
			continue
		}

		if cfg.items[idx].hasval {
			option = fmt.Sprintf("  -%s <%s>", cfg.items[idx].arg, cfg.items[idx].name)
		} else {
			option = fmt.Sprintf("  -%s", cfg.items[idx].arg)
		}

		fmt.Printf("   %-20s : %s\n", option, cfg.items[idx].descr)
	}
}

// Read the command line arguments
// Read the config file values
// Combine the two plus the defaults
func (cfg *Config) read() map[string]string {
	cfgpath := ""

	// These two options are added by default so the program knows where to find the config file
	// and can provide help
	cfg.addOption("help", "help", false, "Output usage information to the console", "no")
	cfg.addOption("cfgpath", "c", true, "Path to configuration file", dfltConf)

	argmap := cfg.readArgs()

	if len(argmap["cfgpath"]) > 0 {
		cfgpath = argmap["cfgpath"]
	} else {
		cfgpath = dfltConf
	}

	confmap, err := readConfigFile(cfgpath)
	if err != nil {
		log.Printf("%v", err)
	}

	return cfg.mergeItems(argmap, confmap)
}

// Read the command line arguments by creating a flag entry for each option, then parsing the flags
func (cfg Config) readArgs() map[string]string {
	args := make(map[string]*string)
	boolargs := make(map[string]*bool)
	combo := make(map[string]string)

	// Options expecting sting arguments, and boolean options (which do not) are added differently
	for idx := 0; idx < len(cfg.items); idx++ {
		if cfg.items[idx].hasval {
			args[cfg.items[idx].name] = flag.String(cfg.items[idx].arg, "", cfg.items[idx].descr)
		} else {
			boolargs[cfg.items[idx].name] = flag.Bool(cfg.items[idx].arg, false, cfg.items[idx].descr)
		}
	}

	flag.Parse()

	// Now that there is a map of pointers to command line options, translate that to a map of strings
	for k, v := range boolargs {
		if *v {
			combo[k] = "yes"
		} else {
			combo[k] = "no"
		}
	}

	for k, v := range args {
		combo[k] = *v
	}

	return combo
}

// If a command line argument is provided, use it, otherwise use the config file value or the default
func merge(arg string, conf string, dflt string) string {
	if len(arg) == 0 {
		if len(conf) != 0 {
			return conf
		} else {
			return dflt
		}
	}

	return arg
}

// Iterate over the list of options, merging the command line, config file and defaults
func (cfg Config) mergeItems(args map[string]string, conf map[string]string) map[string]string {
	mergedmap := make(map[string]string)

	for _, ci := range cfg.items {
		mergedmap[ci.name] = merge(args[ci.name], conf[ci.name], ci.dflt)
	}

	return mergedmap
}

// Debug func to print the current options
func (cfg Config) printOpts() {
	args := cfg.read()

	for k, v := range args {
		fmt.Printf("%s : %s\n", k, v)
	}
}

// Read a config file and return its contents in a map
// There are many Go config file packages available, but most are more complicated than needed here
func readConfigFile(filename string) (map[string]string, error) {
	cfg := make(map[string]string)

	file, err := os.Open(filename)
	if err != nil {
		return cfg, errors.New("Unable to open configuration file. Using default values")
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		// Ignore comment lines
		if strings.HasPrefix(scanner.Text(), "#") {
			continue
		}

		s := strings.SplitN(scanner.Text(), "=", 2)
		// Ignore mal-formed lines
		if len(s) != 2 {
			continue
		}

		// Trim white space from front and back, delete any quotes and make the key lower case
		cfg[strings.ToLower(strings.TrimSpace(s[0]))] = strings.Replace(strings.TrimSpace(s[1]), "\"", "", -1)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return cfg, nil
}
