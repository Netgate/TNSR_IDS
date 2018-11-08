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
	"crypto/tls"
	"sync"
)

const version string = "0.41"
const ACL_WriteRule = "/restconf/data/acl-config/acl-table/acl-list=snortblock/acl-rules"
const ACL_ReadRules = "/restconf/data/acl-config/acl-table/acl-list=snortblock/acl-rules/acl-rule"
const ACL_Delete = "/restconf/data/acl-config/acl-table/acl-list=snortblock/acl-rules/acl-rule="
const MAXCACHEAGE uint64 = 5 // Maximum permitted age of the cached rules after which it must be refreshed
const reapPeriod string = "@every 5m"
const maxSeqNum uint64 = 2147483645
const dfltLogpath = "/var/log/tnsrids/tnsrids.log"

// The ACL structure is nested in a way that allows access each layer
// ACL table structure. This is the next level down after the "acl-config" node
// It contains a list of ACLs
type ACLTable struct {
	AclList []ACL `json:"acl-list"`
}

// Each ACL contains a name and a ACLRuleList
type ACL struct {
	AclName  string      `json:"acl-name"`
	AclRules ACLRuleList `json:"acl-rules"`
}

// An ACLRuleList contains a list of rules
type ACLRuleList struct {
	AclRule []AAclRule `json:"acl-rule"`
}

// Each rule contains a sequence #, description, action and URI (those are all we care about anyway)
type AAclRule struct {
	Sequence           uint64 `json:"sequence"`
	AclRuleDescription string `json:"acl-rule-description"`
	Action             string `json:"action"`
	DstIPPrefix        string `json:"dst-ip-prefix,omitempty"`
	SrcIPPrefix        string `json:"src-ip-prefix,omitempty"`

	/*	In theory the rule could contain these elements, but we are only interested in simple block rules so we don't care
		SrcLastPort        int64  `json:"src-last-port"`
		ICMPFirstCode      int64  `json:"icmp-first-code"`
		ICMPLastCode       int64  `json:"icmp-last-code"`
		ICMPFirstType      int64  `json:"icmp-first-type"`
		TCPFlagsMask       int64  `json:"tcp-flags-mask"`
		SrcFirstPort       int64  `json:"src-first-port"`
		Protocol           int64  `json:"protocol"`
		DstLastPort        int64  `json:"dst-last-port"`
		SrcIPPrefix        string `json:"src-ip-prefix,omitempty"`
		TCPFlagsValue      int64  `json:"tcp-flags-value"`
		ICMPLastType       int64  `json:"icmp-last-type"`
		DstFirstPort       int64  `json:"dst-first-port"`
	*/
}

// Some simple globals
var verbose = false      // Enable verbose logging to stdout
var lastupdate uint64    // When was the cache last updated from TNSR
var tnsrMutex sync.Mutex // Mutex so addRule() and reapACLs() don't collide
var tnsrhost string      // Address or hostname of TNSR instance

// A local copy  of the ACL rules. Certain operations are performed on the cache, which is updated automatically
// when older that MAXCACHEAGE.
// Checking whether a rule exists and calculating the next free sequence number could otherwise require thousands
// of RESTCONF calls
var aclcache ACLRuleList

// Maximum permitted age of the TNSR ACL rules in seconds after which they are removed via reap()
var maxruleage uint64

// Making these global allows the TLS stuff to be set up once, then used on every ESTCONF call
var useTLS bool

// TLS configuration
var tlsConfig *tls.Config

// COnfiguration map. Used only while parsing the command line and config file
var config map[string]string
