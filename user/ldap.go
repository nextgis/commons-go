package users

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"gopkg.in/ldap.v3"

	"github.com/nextgis/commons-go/context"
)

func searchLDAPUser(username string, conn *ldap.Conn) (*ldap.Entry, error) {
	usernameEscaped := ldap.EscapeFilter(username)

	baseDN := context.StringOption("LDAP_BASE_DN")
	filter := context.StringOption("LDAP_USER_FILTER")
	userNameAttribute := context.StringOption("LDAP_USER_ATTR")

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&%s(%s=%s))", filter, userNameAttribute, usernameEscaped),
		[]string{"dn","uid","cn","mail"},
		nil,
	)

	if searchRequest == nil {
		return nil, errors.New("Failed to create request")
	}

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	if len(sr.Entries) > 0 {
		return sr.Entries[0], nil
	}

	return nil, errors.New("User not found or too many entries returned")
}
func createLDAPConnection() (*ldap.Conn, error) {
	url := context.StringOption("LDAP_URL")
	tlsType := context.StringOption("LDAP_TLS")
	tlsNoVerify := context.BoolOption("LDAP_TLS_NO_VERIFY")

	certPath := context.StringOption("LDAP_TLS_CERT_PATH")
	keyPath := context.StringOption("LDAP_TLS_KEY_PATH")

	caCertPath := context.StringOption("LDAP_TLS_CACERT_PATH")

	return createLDAPConnectionInt(url, tlsType, tlsNoVerify, certPath, keyPath, caCertPath)
}

func createLDAPConnectionInt(url string, tlsType string, tlsNoVerify bool, 
	certPath string, keyPath string, caCertPath string) (*ldap.Conn, error) {
	if tlsType == "TLS" || tlsType == "StartTLS" {
		config := &tls.Config{}
		config.InsecureSkipVerify = tlsNoVerify
		if certPath != "" && keyPath != "" {
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return nil, err
			}
	
			config.Certificates = []tls.Certificate{cert}
		}
		if !config.InsecureSkipVerify && caCertPath != "" {
			caCert, err := ioutil.ReadFile(caCertPath)
			if err != nil {
				return nil, err
			}
	
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			config.RootCAs = caCertPool
		}

		config.ServerName = strings.Split(url, ":")[0]

		if tlsType == "TLS" {
			return ldap.DialTLS("tcp", url, config)
		}

		conn, err := ldap.Dial("tcp", url)
		if err != nil {
			return nil, err
		}

		err = conn.StartTLS(config)
		if err != nil {
			return nil, err
		}

		return conn, nil
	}

	return ldap.Dial("tcp", url)
}

// AuthenticateLDAPUser Authenticate LDAP User
func AuthenticateLDAPUser(username string, password string) error {

	connection, err := createLDAPConnection()
	if err != nil {
		return err
	}
	defer connection.Close()

	readerDN := context.StringOption("LDAP_DN")
	passwordDN := context.StringOption("LDAP_DN_PWD")

	err = connection.Bind(readerDN, passwordDN)
	if err != nil {
		return err
	}

	userDN, err := searchLDAPUser(username, connection)
	if err != nil {
		return err
	}

	userGroups := getLDAPGroups(userDN, connection)

	err = connection.Bind(userDN.DN, password)
	if err != nil {
		return errors.New("User is not authorized")
	}

	if len(userGroups) == 0 {
		return errors.New("User not belongs to authorized group")
	}

	return nil
}

func getLDAPUserGroups(username string) ([]string, error) {
	connection, err := createLDAPConnection()
	if err != nil {
		return nil, err
	}
	defer connection.Close()

	readerDN := context.StringOption("LDAP_DN")
	passwordDN := context.StringOption("LDAP_DN_PWD")

	err = connection.Bind(readerDN, passwordDN)
	if err != nil {
		return nil, err
	}

	userDN, err := searchLDAPUser(username, connection)
	if err != nil {
		return nil, err
	}

	userGroups := getLDAPGroups(userDN, connection)

	return userGroups, nil
}

// Get a list of group names for specified user from LDAP/AD
func getLDAPGroups(userDN *ldap.Entry, conn *ldap.Conn) []string {
	groups := make([]string, 0)
	userUID := userDN.GetAttributeValue("uid")
	userDNEscaped := ldap.EscapeFilter(userUID)

	baseDN := context.StringOption("LDAP_BASE_DN")
	groupFilter := context.StringOption("LDAP_GROUP_FILTER")
	groupAttribute := context.StringOption("LDAP_GROUP_ATTR")

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&%s(%s=%s))", groupFilter, groupAttribute, userDNEscaped),
		[]string{"cn"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err == nil {
		for _, entry := range sr.Entries {
			groups = append(groups, entry.GetAttributeValue("cn"))
		}
	} else {
		fmt.Println(err.Error())
	}

	return groups
}

// GetLDAPUserDetails Get LDAP user details
func GetLDAPUserDetails(username string, password string) (string, string, error) {
	connection, err := createLDAPConnection()
	if err != nil {
		return "", "", err
	}
	defer connection.Close()

	readerDN := context.StringOption("LDAP_DN")
	passwordDN := context.StringOption("LDAP_DN_PWD")

	if errb := connection.Bind(readerDN, passwordDN); errb != nil {
		return "", "", errb
	}

	userDN, err := searchLDAPUser(username, connection)
	if err != nil {
		return "", "", err
	}

	userDN.PrettyPrint(2)

	userGroups := getLDAPGroups(userDN, connection)

	// Check password
	if errb := connection.Bind(userDN.DN, password); errb != nil {
		return "", "", errb
	}

	if len(userGroups) < 1 {
		return "", "", errors.New("User not belongs to authorized group")
	}

	fullName := userDN.GetAttributeValue("cn")
	email := userDN.GetAttributeValue("mail")
	return fullName, email, nil
}

// LdapInfo LDAP Info structure
type LdapInfo struct {
	Enable         bool   `form:"enable" json:"enable"`                     // LDAP_LOGIN
	BaseDN         string `form:"base_dn" json:"base_dn"`                   // LDAP_BASE_DN
	UserFilter     string `form:"user_filter" json:"user_filter"`           // LDAP_USER_FILTER
	UserAttribute  string `form:"user_attr" json:"user_attr"`               // LDAP_USER_ATTR
	URL            string `form:"url" json:"url"`                           // LDAP_URL
	TLS            string `form:"tls" json:"tls"`                           // LDAP_TLS
	TLSNoVerify    bool   `form:"tls_no_verify" json:"tls_no_verify"`       // LDAP_TLS_NO_VERIFY
	TLSCertPath    string `form:"tls_cert_path" json:"tls_cert_path"`       // LDAP_TLS_CERT_PATH
	TLSKeyPath     string `form:"tls_key_path" json:"tls_key_path"`         // LDAP_TLS_KEY_PATH
	TLSCaCertPath  string `form:"tls_cacert_path" json:"tls_cacert_path"`   // LDAP_TLS_CACERT_PATH
	DN             string `form:"dn" json:"dn"`                             // LDAP_DN
	DNPassword     string `form:"dn_password" json:"dn_password"`           // LDAP_DN_PWD
	GroupFilter    string `form:"group_filter" json:"group_filter"`         // LDAP_GROUP_FILTER
	GroupAttribute string `form:"group_attr" json:"group_attr"`             // LDAP_GROUP_ATTR
	DefaultGroupID int    `form:"default_group_id" json:"default_group_id"` // LDAP_DEFAULT_GROUP_ID
}

// InitInfo Fill LdapInfo structure by values
func (li *LdapInfo) InitInfo() {
	li.Enable = context.BoolOption("LDAP_LOGIN")
	li.BaseDN = context.StringOption("LDAP_BASE_DN")
	li.UserFilter = context.StringOption("LDAP_USER_FILTER")
	li.UserAttribute = context.StringOption("LDAP_USER_ATTR")
	li.URL = context.StringOption("LDAP_URL")
	li.TLS = context.StringOption("LDAP_TLS")
	li.TLSNoVerify = context.BoolOption("LDAP_TLS_NO_VERIFY")
	li.TLSCertPath = context.StringOption("LDAP_TLS_CERT_PATH")
	li.TLSKeyPath = context.StringOption("LDAP_TLS_KEY_PATH")
	li.TLSCaCertPath = context.StringOption("LDAP_TLS_CACERT_PATH")
	li.DN = context.StringOption("LDAP_DN")
	li.DNPassword = "" //Don't return password context.StringOption("LDAP_DN_PWD")
	li.GroupFilter = context.StringOption("LDAP_GROUP_FILTER")
	li.GroupAttribute = context.StringOption("LDAP_GROUP_ATTR")
	li.DefaultGroupID = context.IntOption("LDAP_DEFAULT_GROUP_ID")
}

// TestLDAPConnection test connection to LDAP server
func TestLDAPConnection(gc *gin.Context) {
	var form LdapInfo
	if err := gc.ShouldBind(&form); err != nil {
		gc.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	connection, err := createLDAPConnectionInt(form.URL, form.TLS, 
		form.TLSNoVerify, form.TLSCertPath, form.TLSKeyPath, form.TLSCaCertPath)
	if err != nil {
		gc.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}
	defer connection.Close()

	err = connection.Bind(form.DN, form.DNPassword)
	if err != nil {
		gc.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	gc.JSON(http.StatusOK, gin.H{"message": "Connected"})
}