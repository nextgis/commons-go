package users

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nextgis/commons-go/context"
)

// TokenJSON Token information
type TokenJSON struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// NGUserInfo User information
type NGUserInfo struct {
	Username       string `json:"username"`
	FirstName      string `json:"first_name"`
	LastName       string `json:"last_name"`
	NGID           string `json:"nextgis_guid"`
	Locale         string `json:"locale"`
	Email          string `json:"email"`
	EmailConfirmed bool   `json:"email_confirmed"`
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
	Enable       bool   `form:"enable" json:"enable"`               // OAUTH_LOGIN
	Endpoint     string `form:"endpoint" json:"endpoint"`           // OAUTH2_ENDPOINT
	ClientID     string `form:"client_id" json:"client_id"`         // OAUTH2_CLIENT_ID
	ClientSecret string `form:"client_secret" json:"client_secret"` // OAUTH2_CLIENT_SECRET
	RedirectURI  string `form:"redirect_uri" json:"redirect_uri"`   // OAUTH2_REDIRECT_URI
}

// InitInfo Init OAuth2 Information
func (oi *OAuth2Info) InitInfo() {
	oi.Enable = context.BoolOption("OAUTH2_LOGIN") 
	oi.ClientID = context.StringOption("OAUTH2_CLIENT_ID")
	oi.ClientSecret = context.StringOption("OAUTH2_CLIENT_SECRET")
	oi.RedirectURI = context.StringOption("OAUTH2_REDIRECT_URI")
	oi.Endpoint = context.StringOption("OAUTH2_ENDPOINT")
}

// GetToken Get access token
func GetToken(code string) (*TokenJSON, error) {
	url := context.StringOption("OAUTH2_ENDPOINT") + "/oauth2/token/?client_id=" +
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

// GetUserInfo Get user information
func GetUserInfo(token *TokenJSON) (*NGUserInfo, error) {
	var netClient = &http.Client{
		Timeout: time.Second * time.Duration(context.IntOption("TIMEOUT")),
	}
	req, err := http.NewRequest("GET", context.StringOption("OAUTH2_ENDPOINT")+"/api/v1/user_info/", nil)
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

	var ui NGUserInfo
	err = json.Unmarshal(bodyBytes, &ui)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse user_info. %s", err.Error())
	}
	return &ui, nil
}

// TokenIntrospection Token introspection
func TokenIntrospection(token *TokenJSON) (*NGTokenInfo, error) {
	var netClient = &http.Client{
		Timeout: time.Second * time.Duration(context.IntOption("TIMEOUT")),
	}
	url := fmt.Sprintf("%s/oauth2/introspect/?token=%s&client_id=%s&client_secret=%s",
	context.StringOption("OAUTH2_ENDPOINT"),
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
	Enabled       bool   `json:"oAuthEnabled"`
	OAuthEndPoint string `json:"oAuthEndpoint"`
	ClientID      string `json:"clientId"`
	RedirectURI   string `json:"redirectURL"`
}

// OAuth2Options Get oauth options: endpoint, cleint_id, etc.
func OAuth2Options(gc *gin.Context) {
	var options = &oauth2Options{
		Enabled:       context.BoolOption("OAUTH2_LOGIN"),
		OAuthEndPoint: context.StringOption("OAUTH2_ENDPOINT"),
		ClientID:      context.StringOption("OAUTH2_CLIENT_ID"),
		RedirectURI:   context.StringOption("OAUTH2_REDIRECT_URI")}
	gc.JSON(http.StatusOK, options)
}
