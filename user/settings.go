package users

import (
	"strings"

	"github.com/nextgis/commons-go/context"
)

// UpdateLocalSettings Update local setting
func UpdateLocalSettings(li *LocalAuthInfo) {
	context.SetBoolOption("LOCAL_LOGIN", li.Enable)
}

// UpdateOAuth2Settings Update oauth2 setting
func UpdateOAuth2Settings(oi *OAuth2Info) {
	context.SetBoolOption("OAUTH2_LOGIN", oi.Enable)
	context.SetBoolOption("OAUTH2_CREATE_GROUPS", oi.CreateGroups)
	context.SetBoolOption("OAUTH2_UPDATE_GROUPS", oi.UpdateGroups)
	
	if len(oi.ClientID) > 0 {
		context.SetStringOption("OAUTH2_CLIENT_ID", oi.ClientID)
	}

	if len(oi.ClientSecret) > 0 {
		context.SetStringOption("OAUTH2_CLIENT_SECRET", oi.ClientSecret)
	}

	if len(oi.RedirectURI) > 0 {
		context.SetStringOption("OAUTH2_REDIRECT_URI", oi.RedirectURI)
	}

	context.SetIntOption("OAUTH2_TYPE", oi.Type)

	if oi.Type == NextGISAuthType {
		if len(oi.Endpoint) > 0 {
			endpoint := oi.Endpoint
			endpoint = strings.TrimSuffix(endpoint, "/")
			
			context.SetStringOption("OAUTH2_ENDPOINT", endpoint)
			context.SetStringOption("OAUTH2_TOKEN_ENDPOINT", endpoint + "/oauth2/token")
			context.SetStringOption("OAUTH2_AUTH_ENDPOINT", endpoint + "/oauth2/authorize")
			context.SetStringOption("OAUTH2_INTROSPECTION_ENDPOINT", endpoint + "/oauth2/introspect")
			context.SetStringOption("OAUTH2_USERINFO_ENDPOINT", endpoint + "/api/v1/user_info")

			context.SetStringOption("OAUTH2_PROFILE_SUBJ_ATTR", "nextgis_guid")
			context.SetStringOption("OAUTH2_PROFILE_KEYNAME_ATTR", "username")
			context.SetStringOption("OAUTH2_PROFILE_FIRSTNAME_ATTR", "first_name")
			context.SetStringOption("OAUTH2_PROFILE_LASTNAME_ATTR", "last_name")
			context.SetStringOption("OAUTH2_SCOPE", "user_info.read")
		}	
	} else if oi.Type == KeycloakAuthType {
		if len(oi.Endpoint) > 0 {
			endpoint := oi.Endpoint
			endpoint = strings.TrimSuffix(endpoint, "/")

			context.SetStringOption("OAUTH2_ENDPOINT", oi.Endpoint)
			context.SetStringOption("OAUTH2_TOKEN_ENDPOINT", endpoint + "/protocol/openid-connect/token")
			context.SetStringOption("OAUTH2_AUTH_ENDPOINT", endpoint + "/protocol/openid-connect/auth")
			context.SetStringOption("OAUTH2_INTROSPECTION_ENDPOINT", endpoint + "/protocol/openid-connect/token/introspect")
			context.SetStringOption("OAUTH2_USERINFO_ENDPOINT", endpoint + "/protocol/openid-connect/userinfo")

			context.SetStringOption("OAUTH2_PROFILE_SUBJ_ATTR", "sub")
			context.SetStringOption("OAUTH2_PROFILE_KEYNAME_ATTR", "preferred_username")
			context.SetStringOption("OAUTH2_PROFILE_FIRSTNAME_ATTR", "first_name")
			context.SetStringOption("OAUTH2_PROFILE_LASTNAME_ATTR", "family_name")
			context.SetStringOption("OAUTH2_SCOPE", "")
		}
	} else {
		if len(oi.TokenEndpoint) > 0 {
			context.SetStringOption("OAUTH2_TOKEN_ENDPOINT", strings.TrimSuffix(oi.TokenEndpoint, "/"))
		}
		if len(oi.AuthEndpoint) > 0 {
			context.SetStringOption("OAUTH2_AUTH_ENDPOINT", strings.TrimSuffix(oi.AuthEndpoint, "/"))
		}
		if len(oi.IntrospectionEndpoint) > 0 {
			context.SetStringOption("OAUTH2_INTROSPECTION_ENDPOINT", strings.TrimSuffix(oi.IntrospectionEndpoint, "/"))
		}
		if len(oi.UserInfoEndpoint) > 0 {
			context.SetStringOption("OAUTH2_USERINFO_ENDPOINT", strings.TrimSuffix(oi.UserInfoEndpoint, "/"))
		}

		if len(oi.SubjAttribute) > 0 {
			context.SetStringOption("OAUTH2_PROFILE_SUBJ_ATTR", oi.SubjAttribute)
		}
		if len(oi.KeynameAttribute) > 0 {
			context.SetStringOption("OAUTH2_PROFILE_KEYNAME_ATTR", oi.KeynameAttribute)
		}
		if len(oi.FirstnameAttribute) > 0 {
			context.SetStringOption("OAUTH2_PROFILE_FIRSTNAME_ATTR", oi.KeynameAttribute)
		}
		if len(oi.LastnameAttribute) > 0 {
			context.SetStringOption("OAUTH2_PROFILE_LASTNAME_ATTR", oi.LastnameAttribute)
		}
		if len(oi.Scope) > 0 {
			context.SetStringOption("OAUTH2_SCOPE", oi.Scope)
		} else {
			context.SetStringOption("OAUTH2_SCOPE", "")
		}
	}
}

// UpdateLDAPSettings Update LDAP settings
func UpdateLDAPSettings(li *LdapInfo) {
	context.SetBoolOption("LDAP_LOGIN", li.Enable)
	if len(li.BaseDN) > 0 {
		context.SetStringOption("LDAP_BASE_DN", li.BaseDN)
	}
	if len(li.UserFilter) > 0 {
		context.SetStringOption("LDAP_USER_FILTER", li.UserFilter)
	}
	if len(li.UserAttribute) > 0 {
		context.SetStringOption("LDAP_USER_ATTR", li.UserAttribute)
	}
	if len(li.URL) > 0 {
		context.SetStringOption("LDAP_URL", li.URL)
	}
	if len(li.TLS) > 0 {
		context.SetStringOption("LDAP_TLS", li.TLS)
	}
	context.SetBoolOption("LDAP_TLS_NO_VERIFY", li.TLSNoVerify)
	if len(li.TLSCertPath) > 0 {
		context.SetStringOption("LDAP_TLS_CERT_PATH", li.TLSCertPath)
	}
	if len(li.TLSKeyPath) > 0 {
		context.SetStringOption("LDAP_TLS_KEY_PATH", li.TLSKeyPath)
	}
	if len(li.TLSCaCertPath) > 0 {
		context.SetStringOption("LDAP_TLS_CACERT_PATH", li.TLSCaCertPath)
	}
	if len(li.DN) > 0 {
		context.SetStringOption("LDAP_DN", li.DN)
	}
	if len(li.DNPassword) > 0 {
		context.SetStringOption("LDAP_DN_PWD", li.DNPassword)
	}
	if len(li.GroupFilter) > 0 {
		context.SetStringOption("LDAP_GROUP_FILTER", li.GroupFilter)
	}
	if len(li.GroupAttribute) > 0 {
		context.SetStringOption("LDAP_GROUP_ATTR", li.GroupAttribute)
	}
	context.SetIntOption("LDAP_DEFAULT_GROUP_ID", li.DefaultGroupID)
}
