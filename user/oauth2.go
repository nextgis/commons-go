/*
 * File: oauth2.go
 * Project: ngcommon
 * File Created: Wednesday, 27th May 2019 1:22:54 am
 * Author: Dmitry Baryshnikov <dmitry.baryshnikov@nextgis.com>
 * -----
 * Last Modified: Sunday, 20th September 2020 1:03:48 am
 * Modified By: Dmitry Baryshnikov, <dmitry.baryshnikov@nextgis.com>
 * -----
 * Copyright 2019 - 2020 NextGIS, <info@nextgis.com>
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
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/getsentry/sentry-go"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/nextgis/commons-go/context"
)

const (
	// NextGISAuthType NextGIS auth type
	NextGISAuthType = 1
	// KeycloakAuthType Keycloak auth type
	KeycloakAuthType = 2
	// CustomAuthType Custom auth type
	CustomAuthType = 3
)

// TokenJSON Token information
type TokenJSON struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// ToSession Save token to session
func (token *TokenJSON)ToSession(session sessions.Session) sessions.Session {
	session.Set("access_token", token.AccessToken)
	session.Set("refresh_token", token.RefreshToken)
	session.Set("token_type", token.TokenType)
	session.Set("expires_in", token.ExpiresIn)
	return session
}

// FromSession Set token from session
func (token *TokenJSON)FromSession(session sessions.Session) {
	token.AccessToken = session.Get("access_token").(string)
	token.RefreshToken = session.Get("refresh_token").(string)
	token.ExpiresIn = session.Get("expires_in").(int)
	token.TokenType = session.Get("token_type").(string)
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
	NGID           string `json:"nextgis_guid"`
	Email          string `json:"email"`
	EmailConfirmed bool   `json:"email_confirmed"`
}

// OAuth2Info OAuth2 Information
type OAuth2Info struct {
	Enable                bool   `form:"enable" json:"enable"`                                 // OAUTH_LOGIN
	Endpoint              string `form:"endpoint" json:"endpoint"`                             // OAUTH2_ENDPOINT
	ClientID              string `form:"client_id" json:"client_id"`                           // OAUTH2_CLIENT_ID
	ClientSecret          string `form:"client_secret" json:"client_secret"`                   // OAUTH2_CLIENT_SECRET
	RedirectURI           string `form:"redirect_uri" json:"redirect_uri"`                     // OAUTH2_REDIRECT_URI
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
}

// InitInfo Init OAuth2 Information
func (oi *OAuth2Info) InitInfo() {
	oi.Enable = context.BoolOption("OAUTH2_LOGIN")
	oi.ClientID = context.StringOption("OAUTH2_CLIENT_ID")
	oi.ClientSecret = context.StringOption("OAUTH2_CLIENT_SECRET")
	oi.RedirectURI = context.StringOption("OAUTH2_REDIRECT_URI")
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
}

// GetToken Get access token
func GetToken(code string) (*TokenJSON, error) {
	var netClient = &http.Client{
		Timeout: time.Second * time.Duration(context.IntOption("TIMEOUT")),
	}

	data := url.Values{}
    data.Set("client_id", context.StringOption("OAUTH2_CLIENT_ID"))
    data.Set("client_secret", context.StringOption("OAUTH2_CLIENT_SECRET"))
    data.Set("grant_type", "authorization_code")
    data.Set("code", code)
	data.Set("redirect_uri", context.StringOption("OAUTH2_REDIRECT_URI"))

	var response *http.Response
	var err error
	if context.IntOption("OAUTH2_TYPE") == NextGISAuthType {
		fullURL := context.StringOption("OAUTH2_TOKEN_ENDPOINT") + "/?" + data.Encode()
		if gin.IsDebugging() {
			fmt.Println(fullURL)
		}
		req, err := http.NewRequest("POST", fullURL, nil)
		if err != nil {
			err := fmt.Errorf("Failed to prepare access token request. %s", err.Error())
			context.CaptureException(err, true)
			return nil, err
		}
		response, err = netClient.Do(req)
	} else {	
		response, err = netClient.PostForm(context.StringOption("OAUTH2_TOKEN_ENDPOINT"), data)
	}
	if err != nil {
		err := fmt.Errorf("Failed to get access token. %s", err.Error())
		context.CaptureException(err, true)
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		err := fmt.Errorf("Failed to get access token. Return status code is %d",
			response.StatusCode)
		context.CaptureException(err, true)
		return nil, err
	}

	bodyBytes, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		err := fmt.Errorf("Failed to get access token. %s", err.Error())
		context.CaptureException(err, true)
		return nil, err
	}
	var token TokenJSON
	err = json.Unmarshal(bodyBytes, &token)
	if err != nil {
		err := fmt.Errorf("Failed to parse access token. %s", err.Error())
		context.CaptureException(err, true)
		return nil, err
	}
	return &token, nil
}

func unmarshalUserInfo(claims map[string]interface{}) *UserInfo {
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
	if val, ok := claims["resource_access"]; ok {
		valM := val.(map[string]interface{})
		if clientVal, ok := valM[context.StringOption("OAUTH2_CLIENT_ID")]; ok {
			clientValM := clientVal.(map[string]interface{})
			if roles, ok := clientValM["roles"]; ok {
				rolesA := roles.([]interface{})
				for _, v := range rolesA {
					ui.Roles = append(ui.Roles, v.(string))
				}
			}
		}
	}

	// NextGIS ID specific
	if val, ok := claims["locale"]; ok {
		ui.Locale = val.(string)
	}
	if val, ok := claims["email"]; ok {
		ui.Email = val.(string)
	}
	if val, ok := claims["email_confirmed"]; ok {
		ui.EmailConfirmed = val.(bool)
	}
	return &ui
}

// GetUserInfo Get user information
func GetUserInfo(token *TokenJSON) (*UserInfo, error) {

	// First try JWT
	jwtVal, err := jwt.Parse(token.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return context.StringOption("OAUTH2_VALIDATE_KEY"), nil
	})
	if err != nil {
		// TODO: Handle error
		context.CaptureException(err, true)
	}

	var ui UserInfo
	if jwtVal != nil {
		if claims, ok := jwtVal.Claims.(jwt.MapClaims); ok {
			ui = *unmarshalUserInfo(claims)
		}

		if len(ui.ID) > 0 {
			return &ui, nil
		}
	}

	// Get user info
	var netClient = &http.Client{
		Timeout: time.Second * time.Duration(context.IntOption("TIMEOUT")),
	}
	req, err := http.NewRequest("GET", context.StringOption("OAUTH2_USERINFO_ENDPOINT"), nil)
	if err != nil {
		err := fmt.Errorf("Failed to prepare user_info request. %s", err.Error())
		context.CaptureException(err, true)
		return nil, err
	}
	req.Header.Add("Authorization", token.TokenType+" "+token.AccessToken)

	response, err := netClient.Do(req)
	if err != nil {
		err := fmt.Errorf("Failed to get user_info. %s", err.Error())
		context.CaptureException(err, true)
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		err := fmt.Errorf("Failed to get user_info. Return status code is %d", response.StatusCode)
		context.CaptureException(err, true)
		return nil, err
	}
	bodyBytes, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		err := fmt.Errorf("Failed to get user_info. %s", err.Error())
		context.CaptureException(err, true)
		return nil, err
	}

	claims := make(map[string]interface{})
	err = json.Unmarshal(bodyBytes, &claims)
	if err != nil {
		err := fmt.Errorf("Failed to parse user_info. %s", err.Error())
		context.CaptureException(err, true)
		return nil, err
	}

	return unmarshalUserInfo(claims), nil
}

// TokenIntrospection Token introspection
func TokenIntrospection(token *TokenJSON) (*IntrospectResponse, error) {
	var netClient = &http.Client{
		Timeout: time.Second * time.Duration(context.IntOption("TIMEOUT")),
	}

	data := url.Values{}
    data.Set("token", token.AccessToken)
	data.Set("client_id", context.StringOption("OAUTH2_CLIENT_ID"))
	data.Set("client_secret", context.StringOption("OAUTH2_CLIENT_SECRET"))
	var response *http.Response
	var err error
	if context.IntOption("OAUTH2_TYPE") == NextGISAuthType {
		response, err = netClient.Get(context.StringOption("OAUTH2_INTROSPECTION_ENDPOINT") + "/?" + data.Encode())
	} else {
		response, err = netClient.PostForm(context.StringOption("OAUTH2_INTROSPECTION_ENDPOINT"), data)
	}
	if err != nil {
		err := fmt.Errorf("Failed to get token introspection. %s", err.Error())
		context.CaptureException(err, true)
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		err := fmt.Errorf("Failed to get token introspection. Return status code is %d", response.StatusCode)
		context.CaptureException(err, true)
		return nil, err
	}
	bodyBytes, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		err := fmt.Errorf("Failed to get token introspection. %s", err.Error())
		context.CaptureException(err, true)
		return nil, err
	}

	var ir IntrospectResponse
	err = json.Unmarshal(bodyBytes, &ir)
	if err != nil {
		err := fmt.Errorf("Failed to parse token introspection. %s", err.Error())
		context.CaptureException(err, true)
		return nil, err
	}
	return &ir, nil
}

// GetSupportInfo Get support information
func GetSupportInfo(token *TokenJSON) (*NGSupportInfo, error) {
	var netClient = &http.Client{
		Timeout: time.Second * time.Duration(context.IntOption("TIMEOUT")),
	}
	req, err := http.NewRequest("GET", context.StringOption("OAUTH2_ENDPOINT")+"/api/v1/support_info/", nil)
	if err != nil {
		err := fmt.Errorf("Failed to prepare support_info request. %s", err.Error())
		context.CaptureException(err, true)
		return nil, err
	}
	req.Header.Add("Authorization", token.TokenType+" "+token.AccessToken)

	response, err := netClient.Do(req)
	if err != nil {
		err := fmt.Errorf("Failed to get support_info. %s", err.Error())
		context.CaptureException(err, true)
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		err := fmt.Errorf("Failed to get support_info. Return status code is %d",
			response.StatusCode)
		context.CaptureException(err, true)
		return nil, err
	}
	bodyBytes, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		context.CaptureException(err, true)
		return nil, fmt.Errorf("Failed to get support_info. %s", err.Error())
	}

	var si NGSupportInfo
	err = json.Unmarshal(bodyBytes, &si)
	if err != nil {
		err := fmt.Errorf("Failed to parse support_info. %s", err.Error())
		context.CaptureException(err, true)
		return nil, err
	}
	return &si, nil
}

type ngUserSupportResult struct {
	Result []NGUserSupportInfo `json:"result"`
}

// GetUserSuppotInfo Get user and support information
func GetUserSuppotInfo(ngID string) (*NGUserSupportInfo, error) {

	if context.IntOption("OAUTH2_TYPE") != NextGISAuthType {
		err := fmt.Errorf("Only support with OAuth2 type %d", NextGISAuthType)
		context.CaptureException(err, true)
		return nil, err
	}

	var netClient = &http.Client{
		Timeout: time.Second * time.Duration(context.IntOption("TIMEOUT")),
	}
	req, err := http.NewRequest("GET", context.StringOption("OAUTH2_ENDPOINT")+
		"/api/v1/integration/user_info/"+ngID+
		"?client_id="+context.StringOption("OAUTH2_CLIENT_ID")+
		"&client_secret="+context.StringOption("OAUTH2_CLIENT_SECRET"), nil)
	if err != nil {
		err := fmt.Errorf("Failed to prepare integration/user_info request. %s", err.Error())
		context.CaptureException(err, true)
		return nil, err
	}
	response, err := netClient.Do(req)
	if err != nil {
		err := fmt.Errorf("Failed to get integration/user_info. %s", err.Error())
		context.CaptureException(err, true)
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		err := fmt.Errorf("Failed to get integration/user_info. Return status code is %d",
			response.StatusCode)
		context.CaptureException(err, true)
		return nil, err
	}
	bodyBytes, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		err := fmt.Errorf("Failed to get user_info. %s", err.Error())
		context.CaptureException(err, true)
		return nil, err
	}

	var usr ngUserSupportResult
	err = json.Unmarshal(bodyBytes, &usr)
	if err != nil {
		err := fmt.Errorf("Failed to parse integration/user_info. %s", err.Error())
		context.CaptureException(err, true)
		return nil, err
	}

	if len(usr.Result) < 1 {
		err := fmt.Errorf("Empty result on integration/user_info request")
		context.CaptureException(err, true)
		return nil, err
	}

	return &usr.Result[0], nil
}

type oauth2Options struct {
	Enabled       bool   `json:"oauth_enabled"`
	OAuthEndPoint string `json:"oauth_endpoint"`
	ClientID      string `json:"client_id"`
	RedirectURI   string `json:"redirect_uri"`
	Scope         string `json:"scope"`
	AltLogins     bool   `json:"alt_logins"`
}

// OAuth2Options Get oauth options: endpoint, cleint_id, etc.
func OAuth2Options(gc *gin.Context) {
	var options = &oauth2Options{
		Enabled:       context.BoolOption("OAUTH2_LOGIN"),
		OAuthEndPoint: context.StringOption("OAUTH2_AUTH_ENDPOINT"),
		ClientID:      context.StringOption("OAUTH2_CLIENT_ID"),
		RedirectURI:   context.StringOption("OAUTH2_REDIRECT_URI"),
		AltLogins:     context.BoolOption("LDAP_LOGIN") || context.BoolOption("LOCAL_LOGIN"),
		Scope:         context.StringOption("OAUTH2_SCOPE"),
	}
	gc.JSON(http.StatusOK, options)
}

// RefreshToken Refresh access token
func RefreshToken(token *TokenJSON, scope string) (*TokenJSON, error) {
	var netClient = &http.Client{
		Timeout: time.Second * time.Duration(context.IntOption("TIMEOUT")),
	}
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
    data.Set("refresh_token", token.RefreshToken)
	data.Set("client_id", context.StringOption("OAUTH2_CLIENT_ID"))
	data.Set("client_secret", context.StringOption("OAUTH2_CLIENT_SECRET"))

	fullScope := context.StringOption("OAUTH2_SCOPE")
	if len(scope) > 0 {
		fullScope += " " + scope
	}

	if len(fullScope) > 0 {
		data.Set("scope", fullScope)
	}

	var response *http.Response
	var err error
	if context.IntOption("OAUTH2_TYPE") == NextGISAuthType {
		fullURL := context.StringOption("OAUTH2_TOKEN_ENDPOINT") + "/?" + data.Encode()
		if gin.IsDebugging() {
			fmt.Println(fullURL)
		}
		req, err := http.NewRequest("POST", fullURL, nil)
		if err != nil {
			err := fmt.Errorf("Failed to prepare refresh token request. %s", err.Error())
			context.CaptureException(err, true)
			return nil, err
		}
		response, err = netClient.Do(req)
	} else {	
		response, err = netClient.PostForm(context.StringOption("OAUTH2_TOKEN_ENDPOINT"), data)
	}

	if err != nil {
		err := fmt.Errorf("Failed to refresh token. %s", err.Error())
		context.CaptureException(err, true)
		return nil, err
	}
	if response == nil {
		err := errors.New("Unexpected error occured")
		sentry.CaptureException(err)
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		// err := fmt.Errorf("Failed to refresh token. Return status code is %d", response.StatusCode)
		// sentry.CaptureException(err)
		return nil, err
	}
	bodyBytes, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		err := fmt.Errorf("Failed to refresh token. %s", err.Error())
		context.CaptureException(err, true)
		return nil, err
	}

	var t TokenJSON
	err = json.Unmarshal(bodyBytes, &t)
	if err != nil {
		err := fmt.Errorf("Failed to parse token. %s", err.Error())
		context.CaptureException(err, true)
		return nil, err
	}
	return &t, nil

}