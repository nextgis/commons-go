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

var contextKey = ""

// Context of an application
type Context struct {
	Config *viper.Viper
}

// StringOption return string settings option
func (c *Context) StringOption(key string) string {
	return c.Config.GetString(key)
}


// BoolOption return boolean settings option
func (c *Context) BoolOption(key string) bool {
	return c.Config.GetBool(key)
}

// IntOption return boolean settings option
func (c *Context) IntOption(key string) int {
	return c.Config.GetInt(key)
}

// DurationOption return time duration option
func (c *Context) DurationOption(key string) time.Duration {
	return c.Config.GetDuration(key)
}

// StringSliceOption return string slice option
func (c *Context) StringSliceOption(key string) []string {
	return c.Config.GetStringSlice(key)
}

// SetStringOption set string option
func (c *Context) SetStringOption(key string, value string) error {
	c.Config.Set(key, value)
	return c.Config.WriteConfig()
}

// SetBoolOption set string option
func (c *Context) SetBoolOption(key string, value bool) error {
	c.Config.Set(key, value)
	return c.Config.WriteConfig()
}

// SetIntOption set string option
func (c *Context) SetIntOption(key string, value int) error {
	c.Config.Set(key, value)
	return c.Config.WriteConfig()
}

// SetUintOption set string option
func (c *Context) SetUintOption(key string, value uint) error {
	c.Config.Set(key, value)
	return c.Config.WriteConfig()
}

// Context Will add the application context to the context
func (c *Context) Context() gin.HandlerFunc {
	return func(cg *gin.Context) {
		cg.Set(contextKey, c)
		cg.Next()
	}
}

// WriteConfig write config
func (c *Context) WriteConfig() error {
	return c.Config.WriteConfig()
}

// SetDefaults Set application defaults
func SetDefaults(appname string) {
	// Common
	viper.SetDefault("DEBUG", true)
	viper.SetDefault("ADMIN_PASSWORD", "admin")
	viper.SetDefault("FILE_STORE", "./" + appname)
	viper.SetDefault("SESSION_KEY", "secret")

	// LDAP
	viper.SetDefault("LDAP_LOGIN", false)
	viper.SetDefault("LDAP_TLS", "No")
	viper.SetDefault("LDAP_URL", "")
	viper.SetDefault("LDAP_USER_FILTER", "(objectClass=posixAccount)")
	viper.SetDefault("LDAP_USER_ATTR", "uid")
	viper.SetDefault("LDAP_GROUP_FILTER", fmt.Sprintf("(cn=%s)", appname))
	viper.SetDefault("LDAP_GROUP_ATTR", "memberUid")
	viper.SetDefault("LDAP_DEFAULT_GROUP_ID", 0)

	// oAuth2
	viper.SetDefault("OAUTH2_LOGIN", false)
	viper.SetDefault("OAUTH2_ENDPOINT", "https://my.nextgis.com")

	contextKey = fmt.Sprintf("github.com/nextgis/%s/context", appname)
}

// CreateSession Create new session and return handler.
func CreateSession(appname string) gin.HandlerFunc {
	secretKey := viper.GetString("SESSION_KEY")
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

// GetConfig return application context
func GetConfig(appname string) *viper.Viper {
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

	return viper.GetViper()
}

// GetContextKey Return context value
func GetContextKey() string {
	return contextKey
}