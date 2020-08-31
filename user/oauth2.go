package users

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
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

// NGTokenInfo NextGIS token information
type NGTokenInfo struct {
	Active   bool   `json:"active"`
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
}

// GetToken Get access token
func GetToken(code string) (*TokenJSON, error) {
	url := context.StringOption("OAUTH2_TOKEN_ENDPOINT") + "?client_id=" +
		context.StringOption("OAUTH2_CLIENT_ID") + "&client_secret=" +
		context.StringOption("OAUTH2_CLIENT_SECRET") + "&grant_type=authorization_code&code=" +
		code + "&redirect_uri=" + context.StringOption("OAUTH2_REDIRECT_URI")
	var netClient = &http.Client{
		Timeout: time.Second * time.Duration(context.IntOption("TIMEOUT")),
	}

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to prepare access token request. %s", err.Error())
	}
	response, err := netClient.Do(req)

	if err != nil {
		return nil, fmt.Errorf("Failed to get access token. %s", err.Error())
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get access token. Return status code is %d",
			response.StatusCode)
	}

	bodyBytes, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("Failed to get access token. %s", err.Error())
	}
	var token TokenJSON
	err = json.Unmarshal(bodyBytes, &token)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse access token. %s", err.Error())
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
				rolesA := roles.([]string)
				for _, v := range rolesA {
					ui.Roles = append(ui.Roles, v)
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
		fmt.Println(err.Error())
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
		return nil, fmt.Errorf("Failed to prepare user_info request. %s", err.Error())
	}
	req.Header.Add("Authorization", token.TokenType+" "+token.AccessToken)

	response, err := netClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Failed to get user_info. %s", err.Error())
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get user_info. Return status code is %d",
			response.StatusCode)
	}
	bodyBytes, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("Failed to get user_info. %s", err.Error())
	}

	claims := make(map[string]interface{})
	err = json.Unmarshal(bodyBytes, &claims)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse user_info. %s", err.Error())
	}

	return unmarshalUserInfo(claims), nil
}

// TokenIntrospection Token introspection
func TokenIntrospection(token *TokenJSON) (*NGTokenInfo, error) {
	var netClient = &http.Client{
		Timeout: time.Second * time.Duration(context.IntOption("TIMEOUT")),
	}
	url := fmt.Sprintf("%s?token=%s&client_id=%s&client_secret=%s",
		context.StringOption("OAUTH2_USERINFO_ENDPOINT"),
		token.AccessToken,
		context.StringOption("OAUTH2_CLIENT_ID"),
		context.StringOption("OAUTH2_CLIENT_SECRET"))
	if gin.IsDebugging() {
		fmt.Printf("Token introspection URL: %s\n", url)
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to prepare token introspection request. %s", err.Error())
	}
	response, err := netClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Failed to get token introspection. %s", err.Error())
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get token introspection. Return status code is %d",
			response.StatusCode)
	}
	bodyBytes, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("Failed to get token introspection. %s", err.Error())
	}

	var ti NGTokenInfo
	err = json.Unmarshal(bodyBytes, &ti)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse token introspection. %s", err.Error())
	}
	return &ti, nil
}

// GetSupportInfo Get support information
func GetSupportInfo(token *TokenJSON) (*NGSupportInfo, error) {
	var netClient = &http.Client{
		Timeout: time.Second * time.Duration(context.IntOption("TIMEOUT")),
	}
	req, err := http.NewRequest("GET", context.StringOption("OAUTH2_ENDPOINT")+"/api/v1/support_info/", nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to prepare support_info request. %s", err.Error())
	}
	req.Header.Add("Authorization", token.TokenType+" "+token.AccessToken)

	response, err := netClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Failed to get support_info. %s", err.Error())
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get support_info. Return status code is %d",
			response.StatusCode)
	}
	bodyBytes, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("Failed to get support_info. %s", err.Error())
	}

	var si NGSupportInfo
	err = json.Unmarshal(bodyBytes, &si)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse support_info. %s", err.Error())
	}
	return &si, nil
}

type ngUserSupportResult struct {
	Result []NGUserSupportInfo `json:"result"`
}

// GetUserSuppotInfo Get user and support information
func GetUserSuppotInfo(ngID string) (*NGUserSupportInfo, error) {

	if context.IntOption("OAUTH2_TYPE") != NextGISAuthType {
		return nil, fmt.Errorf("Only support with OAuth2 type %d", NextGISAuthType)
	}

	var netClient = &http.Client{
		Timeout: time.Second * time.Duration(context.IntOption("TIMEOUT")),
	}
	req, err := http.NewRequest("GET", context.StringOption("OAUTH2_ENDPOINT")+
		"/api/v1/integration/user_info/"+ngID+
		"?client_id="+context.StringOption("OAUTH2_CLIENT_ID")+
		"&client_secret="+context.StringOption("OAUTH2_CLIENT_SECRET"), nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to prepare integration/user_info request. %s", err.Error())
	}
	response, err := netClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Failed to get integration/user_info. %s", err.Error())
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get integration/user_info. Return status code is %d",
			response.StatusCode)
	}
	bodyBytes, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("Failed to get user_info. %s", err.Error())
	}

	var usr ngUserSupportResult
	err = json.Unmarshal(bodyBytes, &usr)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse integration/user_info. %s", err.Error())
	}

	if len(usr.Result) < 1 {
		return nil, fmt.Errorf("Empty result on integration/user_info request")
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
		Scope:         context.StringOption("OSUTH2_SCOPE"),
	}
	gc.JSON(http.StatusOK, options)
}
