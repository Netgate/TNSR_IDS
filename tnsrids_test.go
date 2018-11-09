/* Copyright (c) 2018 Rubicon Communications, LLC (Netgate)
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
	"testing"
	"reflect"
)

// Creat a set of program option and ensure that they are combined in a manner that lets the command line
// override hte config file, or use the defaults if none are providded
func TestMergeItems(t *testing.T) {

	var tconfig Config

	tconfig.addOption("reap", "reap", false, "Reap block rules and exit", "no")
	tconfig.addOption("show", "show", false, "List the current block rules and exit", "no")
	tconfig.addOption("host", "h", true, "Host name of TNSR instance (including protocol prefix", dfltHost)
	tconfig.addOption("port", "p", true, "UDP port on which to listen for alert messages", dfltPort)

	args :=     map[string]string{"host":"192.168.1.4", "port":"",     "show":"",   "reap":"yes"}
	conf :=     map[string]string{"host":"192.168.1.4", "port":"4444", "show":"",   "reap":"no"}  
	expected := map[string]string{"host":"192.168.1.4", "port":"4444", "show":"no", "reap":"yes" }

	received := tconfig.mergeItems(args, conf)

	if ! reflect.DeepEqual(expected, received) {
		t.Errorf("mergeItems() failed. Expected %v but received %v", expected, received)
	}
}

// Ensure that an IPv4 address is properly extracted from an alert string
func TestFindIP(t *testing.T) {
	var tests = []struct {
		alert string
		address string
	} {
		{"This alert contains 172.21.2.4", "172.21.2.4"},
		{"This alert contains 192.168.12.14/22", "192.168.12.14"},
		{"192.168.12.14:9090 is contained in this alert", "192.168.12.14"},
	}

	for _, test := range tests {
		addr := findIP(test.alert)
		if test.address != addr {
			t.Errorf("Expected IP address %s, but got %s", test.address, addr)
		}
	}
}

// Tests the generation of hte next sequence number by creating an aclcache with various sequence number missing a number
// at teh start of the list, in the middle, at the end, of when a sequence # > maxSeqNum
func TestGetNextSeqNum(t *testing.T) {
	var tests = []struct {
		s1 uint64
		s2 uint64
		s3 uint64
		s4 uint64
		next uint64
	} {
		{1,2,3,4,5},
		{2,3,4,5,1},
		{1,2,3,6,4},
		{1,2,3,maxSeqNum+1, 4},
	}

	for _, test := range tests {
		var rule AAclRule
		aclcache.AclRule = aclcache.AclRule[:0] // Clear the list of rules
		rule.Sequence = test.s1
		rule.Action = "deny"
		aclcache.AclRule = append(aclcache.AclRule, rule)
		rule.Sequence = test.s2
		rule.Action = "deny"
		aclcache.AclRule = append(aclcache.AclRule, rule)
		rule.Sequence = test.s3
		rule.Action = "deny"
		aclcache.AclRule = append(aclcache.AclRule, rule)
		rule.Sequence = test.s4
		rule.Action = "deny"
		aclcache.AclRule = append(aclcache.AclRule, rule)

		ns := getNextSeqNum()

		if ns != test.next {
			t.Errorf("Expected sequence number %d but got %d", test.next, ns)
		}
	}
}

// Tests whether the presence of a rule in hte cache can be verified
func TestRuleExists(t *testing.T) {
	aclcache.AclRule = aclcache.AclRule[:0] // Clear the list of rules
	var rule AAclRule

	rule.DstIPPrefix = "192.168.1.100"
	aclcache.AclRule = append(aclcache.AclRule, rule)
	rule.SrcIPPrefix = "192.168.10.100"
	aclcache.AclRule = append(aclcache.AclRule, rule)

	if ruleExists("172.2.2.2") {
		t.Errorf("Host 172.2.2.2 should not exist, but it does")
	}

	if !ruleExists("192.168.1.100") {
		t.Errorf("Dst 192.168.1.100 should exist, but it does not")
	}

	if !ruleExists("192.168.10.100") {
		t.Errorf("Src 192.168.10.100 should exist, but it does not")
	}
}
