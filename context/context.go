/*
 * File: context.go
 * Project: ngcommon
 * File Created: Tuesday, 26th May 2019 6:28:28 pm
 * Author: Dmitry Baryshnikov <dmitry.baryshnikov@nextgis.com>
 * -----
 * Last Modified: Sunday, 20th September 2020 1:03:19 am
 * Modified By: Dmitry Baryshnikov, <dmitry.baryshnikov@nextgis.com>
 * -----
 * Copyright 2019 - 2023 NextGIS, <info@nextgis.com>
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

package context

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/getsentry/sentry-go"
	sentrygin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-contrib/location"
	"github.com/nextgis/go-sessions"
	"github.com/nextgis/go-sessions/memstore"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

const (
	sessionMaxAge = 86400 * 3 // 3d
)

// ContextKey Context key value
var ContextKey = ""

// FileStorePath Path to file store
var FileStorePath = ""

// StringOption return string settings option
func StringOption(key string) string {
	val := viper.GetString(key)
	// Special case for empty string options
	if val == "NONE" {
		return ""
	}
	return viper.GetString(key)
}

// BoolOption return boolean settings option
func BoolOption(key string) bool {
	return viper.GetBool(key)
}

// IntOption return int settings option
func IntOption(key string) int {
	return viper.GetInt(key)
}

// UintOption return uint settings option
func UintOption(key string) uint {
	return viper.GetUint(key)
}

// DurationOption return time duration option
func DurationOption(key string) time.Duration {
	return viper.GetDuration(key)
}

// StringSliceOption return string slice option
func StringSliceOption(key string) []string {
	return viper.GetStringSlice(key)
}

// FloatOption return float option
func FloatOption(key string) float64 {
	return viper.GetFloat64(key)
}

// IntSliceOption return int slice option
func IntSliceOption(key string) []int {
	return viper.GetIntSlice(key)
}

// SetStringOption set string option
func SetStringOption(key string, value string) error {
	viper.Set(key, value)
	return WriteConfig()
}

// SetBoolOption set bool option
func SetBoolOption(key string, value bool) error {
	viper.Set(key, value)
	return WriteConfig()
}

// SetIntOption set int option
func SetIntOption(key string, value int) error {
	viper.Set(key, value)
	return WriteConfig()
}

// SetUintOption set uint option
func SetUintOption(key string, value uint) error {
	viper.Set(key, value)
	return WriteConfig()
}

// SetFloatOption set float option
func SetFloatOption(key string, value float64) error {
	viper.Set(key, value)
	return WriteConfig()
}

// StringSliceOption set string slice option
func SetStringSliceOption(key string, value []string) error {
	viper.Set(key, value)
	return WriteConfig()
}

// SetDefaultOption Set default value to option
func SetDefaultOption(key string, value interface{}) {
	viper.SetDefault(key, value)
}

// SetIntSliceOption set int slice option
func SetIntSliceOption(key string, value []int) error {
	viper.Set(key, value)
	return WriteConfig()
}

// RegisterAlias Register alias for option key
func RegisterAlias(alias, key string) {
	viper.RegisterAlias(alias, key)
}

// CreateContext Will add the application context to the context
func CreateContext(value interface{}) gin.HandlerFunc {
	return func(gc *gin.Context) {
		gc.Set(ContextKey, value)
		gc.Next()
	}
}

// WriteConfig write config
func WriteConfig() error {
	return viper.WriteConfig()
}

var appNameInt string
var appVersionInt string

// GetAppName return application name
func GetAppName() string {
	return appNameInt
}

// GetAppVersion return application version
func GetAppVersion() string {
	return appVersionInt
}

// SetDefaults Set application defaults
func SetDefaults(appName, appVersion string) {
	appNameInt = appName
	appVersionInt = appVersion

	// Common
	SetDefaultOption("DEBUG", true)
	SetDefaultOption("ADMIN_PASSWORD", "admin")
	SetDefaultOption("SESSION_KEY", "secret")
	SetDefaultOption("TOKEN_CACHE_SIZE", 1024)
	SetDefaultOption("TIMEOUT", 180) // Timeout to get remote data
	SetDefaultOption("FILE_TIMEOUT", 1800) // Timeout to get remote data
	SetDefaultOption("SESSION_MAX_AGE", sessionMaxAge)
	SetDefaultOption("HTTP_SKIP_SSL_VERIFY", false)

	// LDAP
	SetDefaultOption("LDAP_LOGIN", false)
	SetDefaultOption("LDAP_TLS", "No")
	SetDefaultOption("LDAP_URL", "")
	SetDefaultOption("LDAP_USER_FILTER", "(objectClass=posixAccount)")
	SetDefaultOption("LDAP_USER_ATTR", "uid")
	SetDefaultOption("LDAP_GROUP_FILTER", fmt.Sprintf("(cn=%s)", appName))
	SetDefaultOption("LDAP_GROUP_ATTR", "memberUid")
	SetDefaultOption("LDAP_DEFAULT_GROUP_ID", 0)
	SetDefaultOption("LDAP_UPDATE_GROUPS", false)

	// oAuth2
	SetDefaultOption("OAUTH2_LOGIN", false)
	SetDefaultOption("OAUTH2_ENDPOINT", "https://my.nextgis.com")
	SetDefaultOption("OAUTH2_SCOPE", "user_info.read")
	SetDefaultOption("OAUTH2_TYPE", 1)
	SetDefaultOption("OAUTH2_TOKEN_ENDPOINT", "https://my.nextgis.com/oauth2/token/")
	SetDefaultOption("OAUTH2_AUTH_ENDPOINT", "https://my.nextgis.com/oauth2/authorize/")
	SetDefaultOption("OAUTH2_USERINFO_ENDPOINT", "https://my.nextgis.com/api/v1/user_info/")
	SetDefaultOption("OAUTH2_INTROSPECTION_ENDPOINT", "https://my.nextgis.com/oauth2/introspect/")
	SetDefaultOption("OAUTH2_PROFILE_SUBJ_ATTR", "nextgis_guid")
	SetDefaultOption("OAUTH2_PROFILE_KEYNAME_ATTR", "username")
	SetDefaultOption("OAUTH2_PROFILE_FIRSTNAME_ATTR", "first_name")
	SetDefaultOption("OAUTH2_PROFILE_LASTNAME_ATTR", "last_name")
	SetDefaultOption("OAUTH2_USER_AUTOCREATE", true)
	SetDefaultOption("OAUTH2_VALIDATE_KEY", "")
	SetDefaultOption("OAUTH2_CREATE_GROUPS", false)
	SetDefaultOption("OAUTH2_UPDATE_GROUPS", false)
	SetDefaultOption("OAUTH2_TOKEN_CACHE_TTL", 3600)
	SetDefaultOption("OAUTH2_LOGOUT_ENDPOINT", "")
	SetDefaultOption("OAUTH2_GROUPS_JWT_KEY", "resource_access/{client_id}/roles")

	// Local
	SetDefaultOption("LOCAL_LOGIN", true)
	SetDefaultOption("DEFAULT_LANGUAGE", "en")
	SetDefaultOption("LOG", false)
	SetDefaultOption("LOG_ONLY_EDITS", false)
	SetDefaultOption("ADMIN_GROUP_NAME", "Administrators")

	ContextKey = fmt.Sprintf("github.com/nextgis/%s/context", appName)
}

// CreateSession Create new session and return handler.
func CreateSession(appname string) gin.HandlerFunc {
	secretKey := StringOption("SESSION_KEY")
	// TODO: https://github.com/wader/gormstore/blob/master/gormstore.go
	store := memstore.NewStore([]byte(secretKey))
	store.Options(sessions.Options{
		MaxAge: IntOption("SESSION_MAX_AGE"), // default MaxAge: 86400 * 30,
		Path:   "/",
		// Secure:   true,
		HttpOnly: true,
	})

	return sessions.Sessions(appname+"_session", store)
}

// DefaultSession is shortcut to get session
func DefaultSession(gc *gin.Context) sessions.Session {
	return gc.MustGet(sessions.DefaultKey).(sessions.Session)
}

// GetSentryHub return Sentry hub from gin context
func GetSentryHub(gc *gin.Context) *sentry.Hub {
	return sentrygin.GetHubFromContext(gc)
}

// CaptureMessage capture message for sentry
func CaptureMessage(msg string, logMessage bool) {
	sentry.CaptureMessage(msg)
	if logMessage {
		fmt.Println(msg)
	}
}

// CaptureException capture error for sentry
func CaptureException(err error, logMessage bool) {
	if err == nil {
		return
	}
	sentry.CaptureException(err)
	if logMessage {
		fmt.Println(err.Error())
	}
}

// CaptureExceptionFromGin capture error from gin for sentry
func CaptureExceptionFromGin(gc *gin.Context, err error, logMessage bool) {
	if err == nil {
		return
	}
	if hub := sentrygin.GetHubFromContext(gc); hub != nil {
		hub.CaptureException(err)
	}
	if logMessage {
		fmt.Println(err.Error())
	}
}

// GetBaseURL return base URL as scheme + host + port
func GetBaseURL(gc *gin.Context) string {
	// Need r.Use(location.Default()) in application to work this
	url := location.Get(gc)
	return url.Scheme + "://" + url.Host
}

// SetupConfig return application context
func SetupConfig(appname string) {
	viper.SetConfigName("config")
	viper.AutomaticEnv()

	configPath := viper.GetString("FILE_STORE")

	if len(configPath) == 0 {
		configPath = "./" + appname
	}
	// Create file store
	os.MkdirAll(configPath, 0755)
	viper.AddConfigPath(configPath)
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("Config file read error: " + err.Error())
	}

	if err := viper.WriteConfigAs(filepath.Join(configPath, "config.yml")); err != nil {
		CaptureException(err, true)
	}

	FileStorePath = configPath
}

// InitSentry initialize Sentry
func InitSentry(release string) gin.HandlerFunc {
	if len(release) == 0 {
		release = fmt.Sprintf("%s@%s", appNameInt, appVersionInt)
	}

	dsn := StringOption("SENTRY_DSN")
	if len(dsn) == 0 {
		return func(gc *gin.Context) {
			gc.Next()
		}
	}
	if err := sentry.Init(sentry.ClientOptions{Dsn: dsn, Release: release}); err != nil {
		CaptureException(fmt.Errorf("sentry initialization failed: %s", err.Error()), true)
		return func(gc *gin.Context) {
			gc.Next()
		}
	}

	return sentrygin.New(sentrygin.Options{Repanic: true})
}

// CreateLocation create location handler
func CreateLocation(host, scheme, headersScheme, headersHost string) gin.HandlerFunc {
	return location.New(location.Config{
		Host:   host,
		Scheme: scheme,
		Headers: location.Headers{
			Scheme: headersScheme,
			Host:   headersHost,
		},
	})
}
