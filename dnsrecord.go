package ipa

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
)

// DNSRecord encapsulates DNS record data returned from IPA DNS Record commands
type DNSRecord struct {
	Dn                         string      `json:"dn"`
	Name                       IpaDNSName  `json:"idnsname"`
	TTL                        IpaInt      `json:"dnsttl"`
	Class                      IpaString   `json:"dnsclass"`
	Record                     interface{} `json:"dnsrecords"`
	Type                       IpaString   `json:"dnstype"`
	Data                       IpaString   `json:"dnsdata"`
	ARecords                   []string    `json:"arecord"`
	APartIPAddress             IpaString   `json:"a_part_ip_address"`
	ACreateReverse             IpaBool     `json:"a_extra_create_reverse"`
	AAAARecords                []string    `json:"aaaarecord"`
	AAAAIPAddress              IpaString   `json:"aaaa_part_ip_address"`
	AAAACreateReverse          IpaBool     `json:"aaaa_extra_create_reverse"`
	A6Records                  []string    `json:"a6record"`
	A6RecordData               IpaString   `json:"a6_part_data"`
	AFSDBRecords               []string    `json:"afsdbrecord"`
	AFSDBSubtype               IpaInt      `json:"afsdb_part_subtype"`
	AFSDBHostname              IpaDNSName  `json:"afsdb_part_hostname"`
	APLRecords                 []string    `json:"aplrecord"`
	CERTRecords                []string    `json:"certrecord"`
	CERTType                   IpaInt      `json:"cert_part_type"`
	CERTKeyTag                 IpaInt      `json:"cert_part_key_tag"`
	CERTAlgorithm              IpaInt      `json:"cert_part_algorithm"`
	CERTCertOrCRL              IpaString   `json:"cert_part_certificate_or_crl"`
	CNameRecords               []string    `json:"cnamerecord"`
	CNAMEHostname              IpaDNSName  `json:"cname_part_hostname"`
	DHCIDRecords               []string    `json:"dhcidrecord"`
	DLVRecords                 []string    `json:"dlvrecord"`
	DLVKeyTag                  IpaInt      `json:"dlv_part_key_tag"`
	DLVAlgorithm               IpaInt      `json:"dlv_part_algorithm"`
	DLVDigestType              IpaInt      `json:"dlv_part_digest_type"`
	DLVDigest                  IpaString   `json:"dlv_part_digest"`
	DNAMERecords               []string    `json:"dnamerecord"`
	DNAMETarget                IpaDNSName  `json:"dname_part_target"`
	DSRecords                  []string    `json:"dsrecord"`
	DSKeyTag                   IpaInt      `json:"ds_part_key_tag"`
	DSAlgorithm                IpaInt      `json:"ds_part_algorithm"`
	DSDigestType               IpaInt      `json:"ds_part_digest_type"`
	DSDigest                   IpaString   `json:"ds_part_digest"`
	HIPRecords                 []string    `json:"hiprecord"`
	IPSECKEYRecords            []string    `json:"ipseckeyrecord"`
	KeyRecords                 []string    `json:"keyrecord"`
	KXRecords                  []string    `json:"kxrecord"`
	KXPreference               IpaInt      `json:"kx_part_preference"`
	KXExchanger                IpaDNSName  `json:"kx_part_exchanger"`
	LOCRecord                  IpaString   `json:"locrecord"`
	LOCDegLat                  IpaInt      `json:"loc_part_lat_deg"`
	LOCMinLat                  IpaInt      `json:"loc_part_lat_min"`
	LOCSecondsLat              IpaFloat    `json:"loc_part_lat_sec"`
	LOCDirectionLat            IpaString   `json:"loc_part_lat_dir"`
	LOCDegLong                 IpaInt      `json:"loc_part_lon_deg"`
	LOCMinLong                 IpaInt      `json:"loc_part_lon_min"`
	LOCSecondsLong             IpaFloat    `json:"loc_part_lon_sec"`
	LOCDirectionLong           IpaString   `json:"loc_part_lon_dir"`
	LOCAltitude                IpaFloat    `json:"loc_part_altitude"`
	LOCSize                    IpaFloat    `json:"loc_part_size"`
	LOCHorizontalPrecision     IpaFloat    `json:"loc_part_h_precision"`
	LOCVerticalPrecision       IpaFloat    `json:"loc_part_v_precision"`
	MXRecords                  []string    `json:"mxrecord"`
	MXPreference               IpaInt      `json:"mx_part_preference"`
	MXExchanger                IpaDNSName  `json:"mx_part_exchanger"`
	NAPTRRecord                IpaString   `json:"naptrrecord"`
	NAPTROrder                 IpaInt      `json:"naptr_part_order"`
	NAPTRPartPreference        IpaInt      `json:"naptr_part_preference"`
	NAPTRFlags                 IpaString   `json:"naptr_part_flags"`
	NAPTRService               IpaString   `json:"naptr_part_service"`
	NAPTRRegexp                IpaString   `json:"naptr_part_regexp"`
	NAPTRReplacement           IpaString   `json:"naptr_part_replacement"`
	NSRecords                  []string    `json:"nsrecord"`
	NSHostname                 IpaDNSName  `json:"ns_part_hostname"`
	NSECRecords                []string    `json:"nsecrecord"`
	PTRRecords                 []string    `json:"ptrrecord"`
	PTRHostname                IpaDNSName  `json:"ptr_part_hostname"`
	RRSIGRecords               []string    `json:"rrsigrecord"`
	RPRecords                  []string    `json:"rprecord"`
	SIGRecords                 []string    `json:"sigrecord"`
	SPVRecords                 []string    `json:"spfrecord"`
	SRVRecords                 []string    `json:"srvrecord"`
	SRVPriority                IpaInt      `json:"srv_part_priority"`
	SRVWeight                  IpaInt      `json:"srv_part_weight"`
	SRVPort                    IpaInt      `json:"srv_part_port"`
	SRVTarget                  IpaDNSName  `json:"srv_part_target"`
	SSHFPRecords               []string    `json:"sshfprecord"`
	SSHFPAlgorithm             IpaInt      `json:"sshfp_part_algorithm"`
	SSHFPFingerprintType       IpaInt      `json:"sshfp_part_fp_type"`
	SSHFPFingerprint           IpaString   `json:"sshfp_part_fingerprint"`
	TLSARecords                []string    `json:"tlsarecord"`
	TLSACertUsage              IpaInt      `json:"tlsa_part_cert_usage"`
	TLSASelector               IpaInt      `json:"tlsa_part_selector"`
	TLSAMatchingType           IpaInt      `json:"tlsa_part_matching_type"`
	TLSACertAssocData          IpaString   `json:"tlsa_part_cert_association_data"`
	TXTRecords                 []string    `json:"txtrecord"`
	TXTData                    IpaString   `json:"txt_part_data"`
	URIRecords                 []string    `json:"urirecord"`
	URIPriority                IpaInt      `json:"uri_part_priority"`
	URIWeight                  IpaInt      `json:"uri_part_weight"`
	URITargetUniformResourceID IpaString   `json:"uri_part_target"`
}

// LDAP Client methods ===================================

// GetDNSRecord gets record ID for specified zone
func (c *LdapClient) GetDNSRecord(rec, zone string) (*string, error) {
	sr, err := c.Search(fmt.Sprintf("idnsname=%s,cn=dns", zone),
		fmt.Sprintf("(idnsname=%s)", rec),
		[]string{"idnsname"})

	if err != nil {
		return nil, err
	}

	if len(sr.Entries) > 1 {
		return nil, errors.New("too many entries returned")
	}

	if len(sr.Entries) < 1 {
		return nil, errors.New("no entries returned")
	}

	uid := sr.Entries[0].GetAttributeValue("idnsname")

	return &uid, nil
}

// DNSRecordExists check if DNS record with specified zone exist
func (c *LdapClient) DNSRecordExists(rec, zone string) (bool, error) {
	sr, err := c.Search(fmt.Sprintf("idnsname=%s,cn=dns", zone),
		fmt.Sprintf("(idnsname=%s)", rec),
		[]string{})

	if err != nil {
		return false, err
	}

	if len(sr.Entries) > 1 {
		return false, errors.New("too many entries returned")
	}

	return len(sr.Entries) == 1, nil
}

// Client methods ===================================

// Fetch DNS zone details by call the FreeIPA user-show method
func (c *Client) GetDNSRecord(rec string, zone string) (*DNSRecord, error) {
	options := map[string]interface{}{"all": true}

	res, err := c.rpc("dnsrecord_show", []string{zone, rec}, options)

	if err != nil {
		return nil, err
	}

	var dnsRec DNSRecord
	err = json.Unmarshal(res.Result.Data, &dnsRec)
	if err != nil {
		return nil, err
	}
	return &dnsRec, nil
}

// Create DNS Record
func (c *Client) CreateDNSRecord(options map[string]interface{}) (*DNSRecord, error) {
	options["version"] = "2.228"

	res, err := c.rpc("dnsrecord_add", []string{}, options)

	if err != nil {
		return nil, err
	}

	var dns DNSRecord
	log.Printf("[TRACE] DNS record: %s", string(res.Result.Data))
	err = json.Unmarshal(res.Result.Data, &dns)
	if err != nil {
		return nil, err
	}

	return &dns, nil
}

// Delete DNS Record
func (c *Client) DeleteDNSRecord(rec, zone string) error {
	var options = map[string]interface{}{
		"version": "2.231",
		"all":     true,
	}

	_, err := c.rpc("dnsrecord_del", []string{zone, rec}, options)

	return err
}

// DNSRecordMod modifies DNS record
func (c *Client) DNSRecordMod(rec, zone, key string, value interface{}) error {
	options := map[string]interface{}{
		key:       value,
		"version": "2.228"}

	_, err := c.rpc("dnsrecord_mod", []string{zone, rec}, options)

	return err
}
