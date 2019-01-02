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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Update the cached rules from the "snortblock" ACL in TNSR
// If the cache is < MAXCACHEAGE minutes old, don't bother UNLESS force is true
func getSnortBlockACL(force bool) error {
	now := time.Now()

	if !force && (lastupdate+(MAXCACHEAGE*60)) > uint64(now.Unix()) {
		return nil
	}

	if verbose {
		fmt.Println("Updating ACL cache")
	}

	response, err := rest("GET", tnsrhost+ACL_ReadRules, "")

	if err != nil {
		log.Fatal(err)
	}

	// Write the received JSON fule list to the local cache
	err = json.Unmarshal(response, &aclcache)

	if err != nil {
		log.Fatal(err)
	}

	// And remember when
	lastupdate = uint64(now.Unix())
	return nil
}

// Print a pretty list of the rules in an ACL
func (c ACLRuleList) listACLs() {
	log.Printf("INFO: Listing ACL block rules for snortblock ACL")

	idx := 0
	var dstsrc string
	var addr string

	for _, v := range c.AclRule {
		var r AAclRule = v

		if len(r.DstIPPrefix) == 0 {
			dstsrc = "Src IP"
			addr = r.SrcIPPrefix
		} else {
			dstsrc = "Dst IP"
			addr = r.DstIPPrefix
		}

		fmt.Printf("%3d Sequence #: %10d, %s %18s, Action: %7s, Description: %s\n",
			idx, r.Sequence, dstsrc, addr, r.Action, r.AclRuleDescription)

		idx++
	}
}

// Retrieve the rules from the snortblock ACL and print them to the console
func showACLs() {
	err := getSnortBlockACL(false)
	if err != nil {
		errors.New("Unable to snortblock read rues from TNSR\n")
		return
	}

	fmt.Println("\nCurrently installed rules in ACL list \"snortblock\"\n--------------------------------------------------")
	aclcache.listACLs()
}

// Add a rule to the snortblock ACL in TNSR and in local cache. src indicates source rule or destination
func addRule(host string, src bool) {

	var rule AAclRule

	tnsrMutex.Lock()
	defer tnsrMutex.Unlock()

	err := getSnortBlockACL(false)
	if err != nil {
		log.Fatal("Unable to snortblock read rues from TNSR\n")
	}

	// DOn't duplicate rules
	if ruleExists(host) {
		if verbose {
			fmt.Printf("Duplicate rule: %s\n", host)
		}

		return
	}

	now := time.Now()

	// Compose a new rule
	rule.AclRuleDescription = fmt.Sprintf("%d, Added by tnsrids", now.Unix())
	rule.Sequence = getNextSeqNum()
	rule.Action = "deny"

	//Source rule or destination?
	if src {
		rule.SrcIPPrefix = host
		rule.DstIPPrefix = ""
	} else {
		rule.DstIPPrefix = host
		rule.SrcIPPrefix = ""
	}

	b, err := json.Marshal(rule)
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	// Compose the JSON formatting
	cmd := "{\"acl-rule\":[" + string(b) + "]}"

	if verbose {
		fmt.Printf("Adding rule for host: %s\n", host)
	}

	log.Printf("INFO: Adding block rule for \"%s\"", host)

	// Add the new rule to TNSR via RESTCONF
	_, err = rest("PUT", fmt.Sprintf("%s%s%s%d", tnsrhost, ACL_WriteRule, "/acl-rule=", getNextSeqNum()), cmd)
	if err != nil {
		log.Printf("Error: %v", err)
	} else {
		// Add the new rule to the cached rule list
		aclcache.AclRule = append(aclcache.AclRule, rule)
	}
}

// Make an HTTP REST call
// Requires the operator (PUT, POST, GET, DELETE etc), the complete URL (including the protocol) and an optional payload
func rest(oper string, url string, payload string) ([]byte, error) {
	var err error
	var req *http.Request
	var client *http.Client
	var resp *http.Response

	if len(payload) == 0 {
		req, err = http.NewRequest(oper, url, nil)
	} else {
		var jsonStr = []byte(payload)

		req, err = http.NewRequest(oper, url, bytes.NewBuffer(jsonStr))
	}

	req.Header.Set("Content-Type", "application/json")

	if useTLS {
		transport := &http.Transport{TLSClientConfig: tlsConfig}
		client = &http.Client{Transport: transport}
		resp, err = client.Do(req)
		if err != nil {
			return nil, err
		}
	} else {
		client = &http.Client{}
	}

	resp, err = client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	//	fmt.Println("response Status:", resp.Status) // Should be "200 OK"

	if resp.StatusCode != 200 {
		return nil, errors.New("RESTCONF operation failed (" + string(resp.Status) + ")")
	}

	contents, err := ioutil.ReadAll(resp.Body)

	return contents, nil
}

// Returns true if a rule exists for the specified host in the local cache
// Called from functions that have updated the cache already
func ruleExists(host string) bool {
	for _, v := range aclcache.AclRule {
		if host == v.DstIPPrefix || host == v.SrcIPPrefix {
			return true
		}
	}

	return false
}

// Find the lowest unused sequence number in the cached rule list
// This may be a gap in the sequece from a previously deleted rule, ot it may be the next highest number
func getNextSeqNum() uint64 {
	var idx uint64
	var numRules int64 = int64(len(aclcache.AclRule))
	var ruleCnt int64 = 0
	var max uint64 = 0

	// Find the highest sequence number in use
	for _, v := range aclcache.AclRule {
		if v.Sequence > max && v.Action == "deny" {
			max = v.Sequence
		}
	}

	// For every possible number <= max
	for idx = 1; idx < max; idx++ {
		ruleCnt = 0
		// See if there is a rule that uses it as a sequence number
		for _, v := range aclcache.AclRule {
			ruleCnt++
			if idx == v.Sequence {
				break
			}

		}

		// If there was a gap, resuse it
		if ruleCnt == numRules {
			return idx
		}
	}

	// If there was no gap, return the next number
	return max + 1
}

// Delete the rule with the specified sequece number
func deleteRule(seq uint64) error {

	var url string = fmt.Sprintf("%s%s%d", tnsrhost, ACL_Delete, seq)

	_, err := rest("DELETE", url, "")

	if err != nil {
		return (err)
	}

	return nil
}

// Clean out any rules that have a timestamp older than MAXAGEMINS minutes, no timestamp at all
// Ignore the defalut permit rule (which has a seq # > maxSeqNum)
func reapACLs() error {
	deletedSome := false

	if verbose {
		fmt.Println("Cleaning out the old rules")
	}

	// Lock the mutex so that it is not possible to write new rule while reaping old ones
	tnsrMutex.Lock()
	defer tnsrMutex.Unlock()

	var i uint64
	var err error

	err = getSnortBlockACL(false)
	if err != nil {
		return errors.New("Unable to read snortblock rules from TNSR\n")
	}

	now := time.Now()
	epoch := uint64(now.Unix())
	var zapit bool

	for _, v := range aclcache.AclRule {
		// Leave the default permit rule alone
		if v.Sequence > maxSeqNum {
			continue
		}

		zapit = false
		if !strings.Contains(v.AclRuleDescription, ",") {
			log.Printf("INFO: Unable to read timestamp from description. Deleting rule")
			zapit = true
		} else {
			s := strings.Split(v.AclRuleDescription, ",")

			i, err = strconv.ParseUint(s[0], 10, 64)

			if err != nil || i == 0 {
				log.Printf("INFO: Unable to read timestamp from description. Deleting rule")
				zapit = true
			}
		}

		if zapit || (i+maxruleage) < epoch {
			if verbose {
				fmt.Printf("Deleting rule with sequence %v\n", v.Sequence)
			}

			log.Printf("INFO: Reaping rule with sequence %v\n", v.Sequence)
			deleteRule(v.Sequence)
			deletedSome = true
		}
	}

	// Re-read the ACL so that the cache is up to date
	if deletedSome {
		err = getSnortBlockACL(true)
		if err != nil {
			return errors.New("Unable to re-read snortblock rues from TNSR\n")
		}
	}

	return nil
}

// Set up the TLS configuration from the provided ca, certificate and key
func TLSSetup(ca string, certificate string, key string) error {

	if len(ca) == 0 || len(certificate) == 0 || len(key) == 0 {
		return nil
	}

	if verbose {
		fmt.Println("Attempting TLS initialization")
	}

	// Load client cert
	cert, err := tls.LoadX509KeyPair(certificate, key)
	if err != nil {
		return err
	}

	// Load CA cert
	caCert, err := ioutil.ReadFile(ca)
	if err != nil {
		return err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Setup HTTPS client
	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	tlsConfig.BuildNameToCertificate()
	useTLS = true

	return nil
}
