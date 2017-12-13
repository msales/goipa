// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"os"

)

func newTestClient() *Client {
	host := os.Getenv("GOIPA_TEST_HOST")
	keytab := os.Getenv("GOIPA_TEST_KEYTAB")

	return &Client{KeyTab: keytab, Host: host}
}