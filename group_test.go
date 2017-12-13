// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"os"
	"testing"
)

func TestGetGroup(t *testing.T) {
	c := newTestClient()

	user := os.Getenv("GOIPA_TEST_USER")
	pass := os.Getenv("GOIPA_TEST_PASSWD")
	_, err := c.Login(user, pass)
	if err != nil {
		t.Error(err)
	}

	rec, err := c.GetGroup(user)

	if err != nil {
		t.Error(err)
	}

	if string(rec.Gid) != user {
		t.Errorf("Invalid group")
	}
}


func TestGroupExists(t *testing.T) {
	c := newTestClient()

	user := os.Getenv("GOIPA_TEST_USER")
	pass := os.Getenv("GOIPA_TEST_PASSWD")
	_, err := c.Login(user, pass)
	if err != nil {
		t.Error(err)
	}

	exists, err := c.GroupExists(user)

	if err != nil {
		t.Error(err)
	}

	if !exists {
		t.Error("User should exist")
	}

	exists, err = c.GroupExists("safjhkgfdhjkfsehkjfsd")

	if err != nil {
		t.Error(err)
	}

	if exists {
		t.Error("Group should not exist")
	}
}

func TestGroupAddRemoveMember(t *testing.T) {
	c := newTestClient()

	admin_user := os.Getenv("GOIPA_ADMIN_USER")
	admin_pass := os.Getenv("GOIPA_ADMIN_PASSWD")
	user := os.Getenv("GOIPA_TEST_USER")

	_, err := c.Login(admin_user, admin_pass)
	if err != nil {
		t.Error(err)
	}

	err = c.GroupAddUser("data4", user)

	if err != nil {
		t.Error(err)
	}

	err = c.GroupRemoveUser("data4", user)
	if err != nil {
		t.Error(err)
	}
}

func TestCreateDeleteGroup(t *testing.T) {
	c := newTestClient()

	user := os.Getenv("GOIPA_ADMIN_USER")
	pass := os.Getenv("GOIPA_ADMIN_PASSWD")
	_, err := c.Login(user, pass)
	if err != nil {
		t.Error(err)
	}

	rec, err := c.CreateGroup("test_group", "AARGH", "")

	if err != nil {
		t.Error(err)
	}

	if string(rec.Gid) != "test_group" {
		t.Errorf("Invalid group")
	}

	if string(rec.Description) != "AARGH" {
		t.Errorf("Invalid group")
	}

	err = c.DeleteGroup("test_group")
	if err != nil {
		t.Error(err)
	}
}