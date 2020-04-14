// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/davecgh/go-spew/spew"
)

// DNSZone encapsulates DNS DNSZone data returned from ipa DNS commands
type DNSZone struct {
	Dn                       string     `json:"dn"`
	Name                     IpaDNSName `json:"idnsname"`
	NameFromIP               IpaString  `json:"name_from_ip"`
	Active                   IpaBool    `json:"idnszoneactive"`
	Forwarders               []string   `json:"idnsforwarders"`
	ForwardPolicy            IpaString  `json:"idnsforwardpolicy"`
	ManagedBy                IpaString  `json:"managedby"`
	AuthoritativeNameserver  IpaDNSName `json:"idnssoamname"`
	AdministratorEmail       IpaDNSName `json:"idnssoarname"`
	SOASerial                IpaInt     `json:"idnssoaserial"`
	SOARefresh               IpaInt     `json:"idnssoarefresh"`
	SOARetry                 IpaInt     `json:"idnssoaretry"`
	SOAExpire                IpaInt     `json:"idnssoaexpire"`
	SOAMinimum               IpaInt     `json:"idnssoaminimum"`
	TTL                      IpaInt     `json:"dnsttl"`
	DefaultTTL               IpaInt     `json:"dnsdefaultttl"`
	DNSClass                 IpaString  `json:"dnsclass"`
	BINDUpdatePolicy         IpaString  `json:"idnsupdatepolicy"`
	DynamicUpdate            IpaBool    `json:"idnsallowdynupdate"`
	AllowQuery               IpaString  `json:"idnsallowquery"`
	AllowTransfer            IpaString  `json:"idnsallowtransfer"`
	AllowPTRSync             IpaBool    `json:"idnsallowsyncptr"`
	AllowInLineDNSSECSigning IpaBool    `json:"idnssecinlinesigning"`
	NSEC3ParamRecord         IpaString  `json:"nsec3paramrecord"`
}

func (c *LdapClient) GetDNSZone(ns string) (*string, error) {
	sr, err := c.Search("cn=dns",
		fmt.Sprintf("(idnsname=%s)", ns),
		[]string{"idnsname"})

	if err != nil {
		return nil, err
	}

	if len(sr.Entries) > 1 {
		log.Printf(spew.Sdump(sr.Entries))
		return nil, errors.New("too many entries returned")
	}

	if len(sr.Entries) < 1 {
		return nil, errors.New("no entries returned")
	}

	uid := sr.Entries[0].GetAttributeValue("idnsname")

	return &uid, nil
}

func (c *LdapClient) DNSZoneExists(ns string) (bool, error) {
	sr, err := c.Search("cn=dns",
		fmt.Sprintf("(idnsname=%s)", ns),
		[]string{})

	if err != nil {
		return false, err
	}

	if len(sr.Entries) > 1 {
		return false, errors.New("too many entries returned")
	}

	return len(sr.Entries) == 1, nil
}

// Fetch DNS zone details by call the FreeIPA user-show method
func (c *Client) GetDNSZone(ns string) (*DNSZone, error) {
	options := map[string]interface{}{"all": true}

	res, err := c.rpc("dnszone_show", []string{ns}, options)

	if err != nil {
		return nil, err
	}

	var dnsRec DNSZone
	err = json.Unmarshal(res.Result.Data, &dnsRec)
	if err != nil {
		return nil, err
	}
	return &dnsRec, nil
}

// Create DNS DNSZone
func (c *Client) CreateDNSZone(options map[string]interface{}) (*DNSZone, error) {
	options["version"] = "2.228"

	res, err := c.rpc("dnszone_add", []string{}, options)

	if err != nil {
		return nil, err
	}

	var dns DNSZone
	log.Printf("[TRACE] DNS zone: %s", string(res.Result.Data))
	err = json.Unmarshal(res.Result.Data, &dns)
	if err != nil {
		return nil, err
	}

	return &dns, nil
}

// Delete DNS Zone
func (c *Client) DeleteDNSZone(ns string) error {
	var options = map[string]interface{}{
		"version": "2.231"}

	_, err := c.rpc("dnszone_del", []string{ns}, options)

	return err
}

func (c *Client) DNSZoneMod(ns string, key string, value interface{}) error {
	options := map[string]interface{}{
		key:       value,
		"version": "2.228"}

	_, err := c.rpc("dnszone_mod", []string{ns}, options)

	return err
}
