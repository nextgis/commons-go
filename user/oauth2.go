/*
 * File: oauth2.go
 * Project: ngcommon
 * File Created: Wednesday, 27th May 2019 1:22:54 am
 * Author: Dmitry Baryshnikov <dmitry.baryshnikov@nextgis.com>
 * -----
 * Last Modified: Sunday, 20th September 2020 1:03:48 am
 * Modified By: Dmitry Baryshnikov, <dmitry.baryshnikov@nextgis.com>
 * -----
 * Copyright 2019-2023 NextGIS, <info@nextgis.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *   This program is distributed in the hope that it will be useful
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package users

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/nextgis/go-sessions"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/nextgis/commons-go/context"
	"github.com/nextgis/commons-go/util"
)

const (
	// NextGISAuthType NextGIS auth type
	NextGISAuthType = 1
	// KeycloakAuthType Keycloak auth type
	KeycloakAuthType = 2
	// CustomAuthType Custom auth type
	CustomAuthType = 3
	// BlitzAuthType Blitz auth type
	BlitzAuthType = 4
)

const (
	NextGISPlanFree    = 0
	NextGISPlanMini    = 1
	NextGISPlanPremium = 2
)

// TokenJSON Token information
type TokenJSON struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// ToSession Save token to session
func (token *TokenJSON) ToSession(session sessions.Session) sessions.Session {
	session.Set("access_token", token.AccessToken)
	session.Set("refresh_token", token.RefreshToken)
	session.Set("token_type", token.TokenType)
	session.Set("expires_in", token.ExpiresIn)
	return session
}

// FromSession Set token from session
func (token *TokenJSON) FromSession(session sessions.Session) {
	val := session.Get("access_token")
	if val != nil {
		token.AccessToken = val.(string)
	}
	val = session.Get("refresh_token")
	if val != nil {
		token.RefreshToken = val.(string)
	}
	val = session.Get("expires_in")
	if val != nil {
		token.ExpiresIn = val.(int)
	}
	val = session.Get("token_type")
	if val != nil {
		token.TokenType = val.(string)
	}
}

// UserInfo User information
type UserInfo struct {
	Username       string   `json:"username"`
	FirstName      string   `json:"first_name"`
	LastName       string   `json:"last_name"`
	ID             string   `json:"guid"`
	Locale         string   `json:"locale"`
	Email          string   `json:"email"`
	EmailConfirmed bool     `json:"email_confirmed"`
	Plan           int      `json:"subscription_plan"`
	WebGISList     []string `json:"available_webgises"`
	Roles          []string `json:"roles"`
}

// NGSupportInfo Support information
type NGSupportInfo struct {
	Supported bool   `json:"supported"`
	StartDate string `json:"start_date"`
	EndDate   string `json:"end_date"`
	NGID      string `json:"nextgis_guid"`
	Sign      string `json:"sign"`
}

// See https://github.com/nextgis/nextgisid/wiki/Introspection

// IntrospectResponse Introspect response information
type IntrospectResponse struct {
	Active   bool   `json:"active" binding:"required"`
	Exp      int64  `json:"exp"`
	Scopes   string `json:"scope"`
	Username string `json:"username"`
	NGID     string `json:"nextgis_guid"`
}

// NGUserSupportInfo NextGIS user and support information
type NGUserSupportInfo struct {
	Username       string `json:"username"`
	FirstName      string `json:"first_name"`
	LastName       string `json:"last_name"`
	Supported      bool   `json:"supported"`
	StartDate      string `json:"start_date"`
	EndDate        string `json:"end_date"`
	NGID           string `json:"nextgis_guid" binding:"required"`
	Email          string `json:"email"`
	EmailConfirmed bool   `json:"email_confirmed"`
}

// OAuth2Info OAuth2 Information
type OAuth2Info struct {
	Enable                bool   `form:"enable" json:"enable"`                                 // OAUTH_LOGIN
	Endpoint              string `form:"endpoint" json:"endpoint"`                             // OAUTH2_ENDPOINT
	ClientID              string `form:"client_id" json:"client_id"`                           // OAUTH2_CLIENT_ID
	ClientSecret          string `form:"client_secret" json:"client_secret"`                   // OAUTH2_CLIENT_SECRET
	Scope                 string `form:"scope" json:"scope"`                                   // OAUTH2_SCOPE
	Type                  int    `form:"type" json:"type" binding:"required"`                  // OAUTH2_TYPE
	TokenEndpoint         string `form:"token_endpoint" json:"token_endpoint"`                 // OAUTH2_TOKEN_ENDPOINT
	AuthEndpoint          string `form:"auth_endpoint" json:"auth_endpoint"`                   // OAUTH2_AUTH_ENDPOINT
	UserInfoEndpoint      string `form:"userinfo_endpoint" json:"userinfo_endpoint"`           // OAUTH2_USERINFO_ENDPOINT
	IntrospectionEndpoint string `form:"introspection_endpoint" json:"introspection_endpoint"` // OAUTH2_INTROSPECTION_ENDPOINT
	SubjAttribute         string `form:"subj_attr" json:"subj_attr"`                           // OAUTH2_PROFILE_SUBJ_ATTR
	KeynameAttribute      string `form:"keyname_attr" json:"keyname_attr"`                     // OAUTH2_PROFILE_KEYNAME_ATTR
	FirstnameAttribute    string `form:"firstname_attr" json:"firstname_attr"`                 // OAUTH2_PROFILE_FIRSTNAME_ATTR
	LastnameAttribute     string `form:"lastname_attr" json:"lastname_attr"`                   // OAUTH2_PROFILE_LASTNAME_ATTR
	CreateGroups          bool   `form:"create_groups" json:"create_groups"`                   // OAUTH2_CREATE_GROUPS
	UpdateGroups          bool   `form:"update_groups" json:"update_groups"`                   // OAUTH2_UPDATE_GROUPS
	UserAutocreate        bool   `form:"user_autocreate" json:"user_autocreate"`               // OAUTH2_USER_AUTOCREATE
	LogoutEndpoint        string `form:"logout_endpoint" json:"logout_endpoint"`               // OAUTH2_LOGOUT_ENDPOINT
	GroupsJWTKey          string `form:"groups_jwt_key" json:"groups_jwt_key"`                 // OAUTH2_GROUPS_JWT_KEY
}

// Fill Init OAuth2 Information
func (oi *OAuth2Info) Fill() {
	oi.Enable = context.BoolOption("OAUTH2_LOGIN")
	oi.ClientID = context.StringOption("OAUTH2_CLIENT_ID")
	oi.ClientSecret = context.StringOption("OAUTH2_CLIENT_SECRET")
	oi.Endpoint = context.StringOption("OAUTH2_ENDPOINT")
	oi.Scope = context.StringOption("OAUTH2_SCOPE")
	oi.Type = context.IntOption("OAUTH2_TYPE")
	oi.TokenEndpoint = context.StringOption("OAUTH2_TOKEN_ENDPOINT")
	oi.AuthEndpoint = context.StringOption("OAUTH2_AUTH_ENDPOINT")
	oi.UserInfoEndpoint = context.StringOption("OAUTH2_USERINFO_ENDPOINT")
	oi.IntrospectionEndpoint = context.StringOption("OAUTH2_INTROSPECTION_ENDPOINT")
	oi.SubjAttribute = context.StringOption("OAUTH2_PROFILE_SUBJ_ATTR")
	oi.KeynameAttribute = context.StringOption("OAUTH2_PROFILE_KEYNAME_ATTR")
	oi.FirstnameAttribute = context.StringOption("OAUTH2_PROFILE_FIRSTNAME_ATTR")
	oi.LastnameAttribute = context.StringOption("OAUTH2_PROFILE_LASTNAME_ATTR")
	oi.CreateGroups = context.BoolOption("OAUTH2_CREATE_GROUPS")
	oi.UpdateGroups = context.BoolOption("OAUTH2_UPDATE_GROUPS")
	oi.UserAutocreate = context.BoolOption("OAUTH2_USER_AUTOCREATE")
	oi.LogoutEndpoint = context.StringOption("OAUTH2_LOGOUT_ENDPOINT")
	oi.GroupsJWTKey = context.StringOption("OAUTH2_GROUPS_JWT_KEY")
}

// Keycloak configuration URL
// http://s2.nextgis.com/auth/realms/master/.well-known/openid-configuration

// OAuth2Logout Logout from oauth
func OAuth2Logout(token *TokenJSON, headers map[string]string) error {
	// https://www.keycloak.org/docs/latest/securing_apps/index.html#logout

	// tr := &http.Transport{
	// 	TLSClientConfig: &tls.Config{InsecureSkipVerify: context.BoolOption("HTTP_SKIP_SSL_VERIFY")},
	// }
	// var netClient = &http.Client{
	// 	Transport: tr,
	// 	Timeout:   time.Second * time.Duration(context.IntOption("TIMEOUT")),
	// }

	data := url.Values{}
	data.Set("refresh_token", token.RefreshToken)
	url := context.StringOption("OAUTH2_LOGOUT_ENDPOINT")
	var err error
	clientID := context.StringOption("OAUTH2_CLIENT_ID")
	clientSecret := context.StringOption("OAUTH2_CLIENT_SECRET")
	if context.IntOption("OAUTH2_TYPE") == BlitzAuthType {
		_, err = util.PostRemoteForm(url, clientID, clientSecret, 
			map[string]string{}, data)
	} else {
		data.Set("client_id", clientID)
		data.Set("client_secret", clientSecret)
		_, err = util.PostRemoteForm(url, "", "", headers, data)
	}
	if err != nil {
		err := fmt.Errorf("failed to logout. %s", err.Error())
		context.CaptureException(err, gin.IsDebugging())
		return err
	}
	return nil
}

func getToken(data url.Values) (*TokenJSON, error) {
	// tr := &http.Transport{
	// 	TLSClientConfig: &tls.Config{InsecureSkipVerify: context.BoolOption("HTTP_SKIP_SSL_VERIFY")},
	// }
	// var netClient = &http.Client{
	// 	Transport: tr,
	// 	Timeout:   time.Second * time.Duration(context.IntOption("TIMEOUT")),
	// }
// 

	url := context.StringOption("OAUTH2_TOKEN_ENDPOINT")
	var err error
	clientID := context.StringOption("OAUTH2_CLIENT_ID")
	clientSecret := context.StringOption("OAUTH2_CLIENT_SECRET")
	var bodyBytes []byte
	if context.IntOption("OAUTH2_TYPE") == BlitzAuthType {
		bodyBytes, err = util.PostRemoteForm(url, clientID, clientSecret, 
			map[string]string{}, data)
	} else { 
		data.Set("client_id", clientID)
		data.Set("client_secret", clientSecret)
		bodyBytes, err = util.PostRemoteForm(url, "", "", map[string]string{}, 
			data)
	}
	if err != nil {
		err := fmt.Errorf("failed to get access token. %s", err.Error())
		context.CaptureException(err, gin.IsDebugging())
		return nil, err
	}
	var token TokenJSON
	err = json.Unmarshal(bodyBytes, &token)
	if err != nil {
		err := fmt.Errorf("failed to parse access token. %s", err.Error())
		context.CaptureException(err, gin.IsDebugging())
		return nil, err
	}
	return &token, nil
}

// GetToken Get access token
func GetToken(code, redirectURI, query string) (*TokenJSON, error) {
	if len(query) > 0 {
		redirectURI += query
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)

	return getToken(data)
}

// GetTokenByClientSecret Get access token for client id and client secret
func GetTokenByClientSecret() (*TokenJSON, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")

	return getToken(data)
}

func unmarshalUserInfo(claims map[string]interface{}) UserInfo {
	var ui UserInfo
	if val, ok := claims[context.StringOption("OAUTH2_PROFILE_KEYNAME_ATTR")]; ok {
		ui.Username = val.(string)
	}
	if val, ok := claims[context.StringOption("OAUTH2_PROFILE_SUBJ_ATTR")]; ok {
		ui.ID = val.(string)
	}
	if val, ok := claims[context.StringOption("OAUTH2_PROFILE_FIRSTNAME_ATTR")]; ok {
		ui.FirstName = val.(string)
	}
	if val, ok := claims[context.StringOption("OAUTH2_PROFILE_LASTNAME_ATTR")]; ok {
		ui.LastName = val.(string)
	}

	// NextGIS ID specific
	// claims map[available_webgises:[https://test-premium.nextgis.com] first_name:NextGIS last_name:Team nextgis_guid:efd7d8be-5f4e-453f-980b-238e46e2eb6a username:test.premium]
	if val, ok := claims["locale"]; ok {
		ui.Locale = val.(string)
	}
	if val, ok := claims["email"]; ok {
		ui.Email = val.(string)
	}
	if val, ok := claims["email_confirmed"]; ok {
		ui.EmailConfirmed = val.(bool)
	}
	if val, ok := claims["subscription_plan"]; ok {
		ui.Plan = NextGISPlanFree
		valStr := val.(string)
		if strings.EqualFold(valStr, "premium") {
			ui.Plan = NextGISPlanPremium
		} else if strings.EqualFold(valStr, "mini") {
			ui.Plan = NextGISPlanMini
		}
	}
	if val, ok := claims["available_webgises"]; ok {
		valArr := val.([]interface{})
		for _, valItem := range valArr {
			ui.WebGISList = append(ui.WebGISList, valItem.(string))
		}
	}

	// Get roles
	groupItems := strings.Split(context.StringOption("OAUTH2_GROUPS_JWT_KEY"), "/")

	var roles []interface{}
	for _, groupItem := range groupItems {
		if strings.EqualFold(groupItem, "{client_id}") {
			groupItem = context.StringOption("OAUTH2_CLIENT_ID")
		}
		if val, ok := claims[groupItem]; ok {
			if claims, ok = val.(map[string]interface{}); !ok {
				if roles, ok = val.([]interface{}); ok {
					break
				} else {
					context.CaptureException(
						fmt.Errorf("cannot find roles in JWT. Stop at %s", groupItem), gin.IsDebugging())
				}
			}
		}
	}

	for _, v := range roles {
		ui.Roles = append(ui.Roles, v.(string))
	}

	if gin.IsDebugging() {
		fmt.Printf("User roles from user info: %v\n", ui.Roles)
	}

	return ui
}

// GetUserInfo Get user information
func GetUserInfo(token *TokenJSON) (UserInfo, error) {

	// First try JWT
	jwtVal, _ := jwt.Parse(token.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return context.StringOption("OAUTH2_VALIDATE_KEY"), nil
	})
	// if err != nil {
	// TODO: Handle error
	// context.CaptureException(err, gin.IsDebugging())
	// }

	var ui UserInfo
	if jwtVal != nil {
		if claims, ok := jwtVal.Claims.(jwt.MapClaims); ok {
			ui = unmarshalUserInfo(claims)
		}

		if len(ui.ID) > 0 {
			return ui, nil
		}
	}

	// Get user info
	bodyBytes, _, err := util.GetRemoteBytes(
		context.StringOption("OAUTH2_USERINFO_ENDPOINT"), "access_token", 
		token.TokenType+" "+token.AccessToken, map[string]string{}) 
	if err != nil {
		err := fmt.Errorf("failed to get user_info. %s", err.Error())
		context.CaptureException(err, gin.IsDebugging())
		return ui, err
	}

	claims := make(map[string]interface{})
	err = json.Unmarshal(bodyBytes, &claims)
	if err != nil {
		err := fmt.Errorf("failed to parse user_info. %s", err.Error())
		context.CaptureException(err, gin.IsDebugging())
		return ui, err
	}

	return unmarshalUserInfo(claims), nil
}

// TokenIntrospection Token introspection
func TokenIntrospection(token *TokenJSON) (*IntrospectResponse, error) {
	data := url.Values{}
	data.Set("token", token.AccessToken)
	var bodyBytes []byte
	var err error
	url := context.StringOption("OAUTH2_INTROSPECTION_ENDPOINT")
	clientID := context.StringOption("OAUTH2_CLIENT_ID")
	clientSecret := context.StringOption("OAUTH2_CLIENT_SECRET")
	if context.IntOption("OAUTH2_TYPE") == NextGISAuthType {
		data.Set("client_id", clientID)
		data.Set("client_secret", clientSecret)
		bodyBytes, _, err = util.GetRemoteBytes(url + "?" + data.Encode(), "", 
			"", map[string]string{})
	} else if context.IntOption("OAUTH2_TYPE") == BlitzAuthType {
		bodyBytes, err = util.PostRemoteForm(url, clientID,
			clientSecret, map[string]string{}, data)
	} else {
		data.Set("client_id", clientID)
		data.Set("client_secret", clientSecret)
		bodyBytes, err = util.PostRemoteForm(url, "", "", map[string]string{}, 
			data)
	}
	if err != nil {
		err := fmt.Errorf("failed to get token introspection. %s [%s]", err.Error(), bodyBytes)
		context.CaptureException(err, gin.IsDebugging())
		return nil, err
	}

	var ir IntrospectResponse
	err = json.Unmarshal(bodyBytes, &ir)
	if err != nil {
		err := fmt.Errorf("failed to parse token introspection. %s", err.Error())
		context.CaptureException(err, gin.IsDebugging())
		return nil, err
	}
	return &ir, nil
}

// GetSupportInfo Get support information
func GetSupportInfo(token *TokenJSON) (*NGSupportInfo, error) {
	bodyBytes, _, err := util.GetRemoteBytes(
		context.StringOption("OAUTH2_ENDPOINT")+"/api/v1/support_info/", 
		"access_token", token.TokenType+" "+token.AccessToken, map[string]string{})
	if err != nil {
		context.CaptureException(err, gin.IsDebugging())
		return nil, fmt.Errorf("failed to get support_info. %s", err.Error())
	}

	var si NGSupportInfo
	err = json.Unmarshal(bodyBytes, &si)
	if err != nil {
		err := fmt.Errorf("failed to parse support_info. %s", err.Error())
		context.CaptureException(err, gin.IsDebugging())
		return nil, err
	}
	return &si, nil
}

// GetUserSuppotInfo Get user and support information
func GetUserSuppotInfo(ngID string) (*NGUserSupportInfo, error) {

	if context.IntOption("OAUTH2_TYPE") != NextGISAuthType {
		err := fmt.Errorf("only support with OAuth2 type %d", NextGISAuthType)
		context.CaptureException(err, gin.IsDebugging())
		return nil, err
	}

	URL := context.StringOption("OAUTH2_ENDPOINT")+
	"/api/v1/integration/user_info/"+ngID+
	"?client_id="+context.StringOption("OAUTH2_CLIENT_ID")+
	"&client_secret="+context.StringOption("OAUTH2_CLIENT_SECRET")
	bodyBytes, _, err := util.GetRemoteBytes(URL, "", "", map[string]string{})
	if err != nil {
		err := fmt.Errorf("failed to get user_info. %s", err.Error())
		context.CaptureException(err, gin.IsDebugging())
		return nil, err
	}

	var usr NGUserSupportInfo
	err = json.Unmarshal(bodyBytes, &usr)
	if err != nil {
		err := fmt.Errorf("failed to parse integration/user_info. %s", err.Error())
		context.CaptureException(err, gin.IsDebugging())
		return nil, err
	}

	return &usr, nil
}

type oauth2Options struct {
	Enabled       bool   `json:"oauth_enabled"`
	OAuthEndPoint string `json:"oauth_endpoint"`
	ClientID      string `json:"client_id"`
	Scope         string `json:"scope"`
	AltLogins     bool   `json:"alt_logins"`
}

// OAuth2Options Get oauth options: endpoint, cleint_id, etc.
// @Summary Get oauth options: endpoint, cleint_id, etc.
// @Tags admin
// @Produce json
// @Success 200 {object} oauth2Options
// @Router /api/oauth2/options [get]
func OAuth2Options(gc *gin.Context) {
	var options = &oauth2Options{
		Enabled:       context.BoolOption("OAUTH2_LOGIN"),
		OAuthEndPoint: context.StringOption("OAUTH2_AUTH_ENDPOINT"),
		ClientID:      context.StringOption("OAUTH2_CLIENT_ID"),
		AltLogins:     context.BoolOption("LOCAL_LOGIN"), // context.BoolOption("LDAP_LOGIN") || 
		Scope:         context.StringOption("OAUTH2_SCOPE"),
	}
	gc.JSON(http.StatusOK, options)
}

// RefreshToken Refresh access token
func RefreshToken(token *TokenJSON, scope string) (*TokenJSON, error) {
	// tr := &http.Transport{
	// 	TLSClientConfig: &tls.Config{InsecureSkipVerify: context.BoolOption("HTTP_SKIP_SSL_VERIFY")},
	// }
	// var netClient = &http.Client{
	// 	Transport: tr,
	// 	Timeout:   time.Second * time.Duration(context.IntOption("TIMEOUT")),
	// }
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", token.RefreshToken)
	clientID := context.StringOption("OAUTH2_CLIENT_ID")
	clientSecret := context.StringOption("OAUTH2_CLIENT_SECRET")

	fullScope := context.StringOption("OAUTH2_SCOPE")
	if len(scope) > 0 {
		fullScope += " " + scope
	}

	if len(fullScope) > 0 {
		data.Set("scope", fullScope)
	}

	var bodyBytes []byte 
	var err error
	url := context.StringOption("OAUTH2_TOKEN_ENDPOINT")
	if context.IntOption("OAUTH2_TYPE") == BlitzAuthType {
		bodyBytes, err = util.PostRemoteForm(url, clientID, clientSecret, 
			map[string]string{}, data)
	} else {
		data.Set("client_id", clientID)
		data.Set("client_secret", clientSecret)
		bodyBytes, err = util.PostRemoteForm(url, "", "", map[string]string{}, 
			data)
	}
	if err != nil {
		err := fmt.Errorf("failed to refresh token. %s", err.Error())
		context.CaptureException(err, gin.IsDebugging())
		return nil, err
	}

	var t TokenJSON
	err = json.Unmarshal(bodyBytes, &t)
	if err != nil {
		err := fmt.Errorf("failed to parse token. %s", err.Error())
		context.CaptureException(err, gin.IsDebugging())
		return nil, err
	}
	return &t, nil
}
