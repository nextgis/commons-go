package context

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-contrib/location"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

// ContextKey Context key value
var ContextKey = ""

// StringOption return string settings option
func StringOption(key string) string {
	return viper.GetString(key)
}


// BoolOption return boolean settings option
func BoolOption(key string) bool {
	return viper.GetBool(key)
}

// IntOption return boolean settings option
func IntOption(key string) int {
	return viper.GetInt(key)
}

// DurationOption return time duration option
func DurationOption(key string) time.Duration {
	return viper.GetDuration(key)
}

// StringSliceOption return string slice option
func StringSliceOption(key string) []string {
	return viper.GetStringSlice(key)
}

// SetStringOption set string option
func SetStringOption(key string, value string) error {
	viper.Set(key, value)
	return WriteConfig()
}

// SetBoolOption set string option
func SetBoolOption(key string, value bool) error {
	viper.Set(key, value)
	return WriteConfig()
}

// SetIntOption set string option
func SetIntOption(key string, value int) error {
	viper.Set(key, value)
	return WriteConfig()
}

// SetUintOption set string option
func SetUintOption(key string, value uint) error {
	viper.Set(key, value)
	return WriteConfig()
}

// SetDefaultOption Set default value to option
func SetDefaultOption(key string, value interface{}) {
	viper.SetDefault(key, value)
}

// CreateContext Will add the application context to the context
func CreateContext(value interface{}) gin.HandlerFunc {
	return func(cg *gin.Context) {
		cg.Set(ContextKey, value)
		cg.Next()
	}
}

// WriteConfig write config
func WriteConfig() error {
	return viper.WriteConfig()
}

// SetDefaults Set application defaults
func SetDefaults(appname string) {
	// Common
	SetDefaultOption("DEBUG", true)
	SetDefaultOption("ADMIN_PASSWORD", "admin")
	SetDefaultOption("SESSION_KEY", "secret")

	// LDAP
	SetDefaultOption("LDAP_LOGIN", false)
	SetDefaultOption("LDAP_TLS", "No")
	SetDefaultOption("LDAP_URL", "")
	SetDefaultOption("LDAP_USER_FILTER", "(objectClass=posixAccount)")
	SetDefaultOption("LDAP_USER_ATTR", "uid")
	SetDefaultOption("LDAP_GROUP_FILTER", fmt.Sprintf("(cn=%s)", appname))
	SetDefaultOption("LDAP_GROUP_ATTR", "memberUid")
	SetDefaultOption("LDAP_DEFAULT_GROUP_ID", 0)

	// oAuth2
	SetDefaultOption("OAUTH2_LOGIN", false)
	SetDefaultOption("OAUTH2_ENDPOINT", "https://my.nextgis.com")
	SetDefaultOption("OAUTH2_SCOPE", "user_info.read")
	SetDefaultOption("OAUTH2_TYPE", 1)
	SetDefaultOption("OAUTH2_TOKEN_ENDPOINT", "https://my.nextgis.com/oauth2/token")
	SetDefaultOption("OAUTH2_AUTH_ENDPOINT", "https://my.nextgis.com/oauth2/authorize")
	SetDefaultOption("OAUTH2_USERINFO_ENDPOINT", "https://my.nextgis.com/api/v1/user_info")
	SetDefaultOption("OAUTH2_INTROSPECTION_ENDPOINT", "https://my.nextgis.com/oauth2/introspect")
	SetDefaultOption("OAUTH2_PROFILE_SUBJ_ATTR", "nextgis_guid")
	SetDefaultOption("OAUTH2_PROFILE_KEYNAME_ATTR", "username")
	SetDefaultOption("OAUTH2_PROFILE_FIRSTNAME_ATTR", "first_name")
	SetDefaultOption("OAUTH2_PROFILE_LASTNAME_ATTR", "last_name")
	SetDefaultOption("OAUTH2_USER_AUTOCREATE", true)
	SetDefaultOption("OAUTH2_VALIDATE_KEY", "")
	SetDefaultOption("OAUTH2_CREATE_GROUPS", false)
	SetDefaultOption("OAUTH2_UPDATE_GROUPS", false)
	SetDefaultOption("OAUTH2_TOKEN_CACHE_TTL", 3600)

	// Local
	SetBoolOption("LOCAL_LOGIN", true)

	ContextKey = fmt.Sprintf("github.com/nextgis/%s/context", appname)
}

// CreateSession Create new session and return handler.
func CreateSession(appname string) gin.HandlerFunc {
	secretKey := StringOption("SESSION_KEY")
	store := cookie.NewStore([]byte(secretKey))
	store.Options(sessions.Options{
		MaxAge: 3600*72,
		Path:   "/",
		// Secure:   true,
		HttpOnly: true,
	})

	return sessions.Sessions(appname + "_session", store)
}

// DefaultSession is shortcut to get session
func DefaultSession(c *gin.Context) sessions.Session {
	return c.MustGet(sessions.DefaultKey).(sessions.Session)
}

// GetBaseURL return base usr as scheme + host + port
func GetBaseURL(gc *gin.Context) string {
	url := location.Get(gc)
	return url.Scheme + "://" + url.Host
}

// SetupConfig return application context
func SetupConfig(appname string) {
	viper.SetConfigName("config")
	viper.AutomaticEnv()

	configPath := viper.GetString("FILE_STORE")

	if len(configPath) < 1 {
		configPath = "./" + appname
	}
	viper.AddConfigPath(configPath)
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("Config file read error: " + err.Error())
	}

	// Create file store
	os.MkdirAll(viper.GetString("FILE_STORE"), 0755)

	if err := viper.WriteConfigAs(filepath.Join(configPath, "config.yml")); err != nil {
		fmt.Println(err.Error())
	}
}
