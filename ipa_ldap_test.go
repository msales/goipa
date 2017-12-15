package ipa

import (
	"os"
	"testing"
	"fmt"
)

func TestLdapConnect(t *testing.T) {
	user := os.Getenv("GOIPA_ADMIN_USER")
	pass := os.Getenv("GOIPA_ADMIN_PASSWD")
	baseDn := os.Getenv("GOIPA_LDAP_BASEDN")
	host := os.Getenv("GOIPA_TEST_HOST")

	c, err := LdapConnect(host, baseDn, user, pass)
	if err != nil {
		t.Error(err)
		return
	}
	defer c.Close()
}


func TestLdapSearch(t *testing.T) {
	user := os.Getenv("GOIPA_ADMIN_USER")
	pass := os.Getenv("GOIPA_ADMIN_PASSWD")
	baseDn := os.Getenv("GOIPA_LDAP_BASEDN")
	host := os.Getenv("GOIPA_TEST_HOST")

	c, err := LdapConnect(host, baseDn, user, pass)
	if err != nil {
		t.Error(err)
		return
	}
	defer c.Close()

	sr, err := c.Search("cn=users,cn=accounts", "(ipaUniqueID=700f8110-a12d-11e7-94f9-f669ff8b2c7c)",[]string{"cn", "dn"})
	if err != nil {
		t.Error(err)
		return
	}
	for _, entry := range sr.Entries {
		fmt.Printf("%s: %v\n", entry.DN, entry.GetAttributeValue("cn"))
	}
}

// TODO: Remove hard-coded values
func TestGetUserForUUID(t *testing.T) {
	user := os.Getenv("GOIPA_ADMIN_USER")
	pass := os.Getenv("GOIPA_ADMIN_PASSWD")
	baseDn := os.Getenv("GOIPA_LDAP_BASEDN")
	host := os.Getenv("GOIPA_TEST_HOST")

	c, err := LdapConnect(host, baseDn, user, pass)
	if err != nil {
		t.Error(err)
		return
	}
	defer c.Close()

	ret, err := c.GetUserForUUID("700f8110-a12d-11e7-94f9-f669ff8b2c7c")

	if err != nil {
		t.Error(err)
	}

	if *ret != "admin" {
		t.Errorf("incorrect user returned - %s", *ret)
	}
}

// TODO: Remove hard-coded values
func TestGetGroupForUUID(t *testing.T) {
	user := os.Getenv("GOIPA_ADMIN_USER")
	pass := os.Getenv("GOIPA_ADMIN_PASSWD")
	baseDn := os.Getenv("GOIPA_LDAP_BASEDN")
	host := os.Getenv("GOIPA_TEST_HOST")

	c, err := LdapConnect(host, baseDn, user, pass)
	if err != nil {
		t.Error(err)
		return
	}
	defer c.Close()

	ret, err := c.GetGroupForUUID("64b47fbc-a134-11e7-a049-f669ff8b2c7c")

	if err != nil {
		t.Error(err)
	}

	if *ret != "data4" {
		t.Errorf("incorrect user returned - %s", *ret)
	}
}

// TODO: Remove hard-coded values
func TestUserExistsForUUID(t *testing.T) {
	user := os.Getenv("GOIPA_ADMIN_USER")
	pass := os.Getenv("GOIPA_ADMIN_PASSWD")
	baseDn := os.Getenv("GOIPA_LDAP_BASEDN")
	host := os.Getenv("GOIPA_TEST_HOST")

	c, err := LdapConnect(host, baseDn, user, pass)
	if err != nil {
		t.Error(err)
		return
	}
	defer c.Close()

	ret, err := c.UserExistsForUUID("700f8110-a12d-11e7-94f9-f669ff8b2c7c")

	if err != nil {
		t.Error(err)
	}

	if !ret {
		t.Errorf("user not found")
		return
	}

	ret, err = c.UserExistsForUUID("800f8110-a12d")

	if err != nil {
		t.Error(err)
	}

	if ret {
		t.Errorf("user shouldn't exist")
		return
	}
}

// TODO: Remove hard-coded values
func TestGroupExistsForUUID(t *testing.T) {
	user := os.Getenv("GOIPA_ADMIN_USER")
	pass := os.Getenv("GOIPA_ADMIN_PASSWD")
	baseDn := os.Getenv("GOIPA_LDAP_BASEDN")
	host := os.Getenv("GOIPA_TEST_HOST")

	c, err := LdapConnect(host, baseDn, user, pass)
	if err != nil {
		t.Error(err)
		return
	}
	defer c.Close()

	ret, err := c.GroupExistsForUUID("64b47fbc-a134-11e7-a049-f669ff8b2c7c")

	if err != nil {
		t.Error(err)
	}

	if !ret {
		t.Errorf("group not found")
		return
	}

	ret, err = c.GroupExistsForUUID("800f8110-a12d")

	if err != nil {
		t.Error(err)
	}

	if ret {
		t.Errorf("group shouldn't exist")
		return
	}
}
