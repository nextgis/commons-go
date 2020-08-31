package util

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// InfinityDate Infinity date
var InfinityDate = time.Date(2100, time.January, 1, 12, 0, 0, 0, time.UTC)
// OutDate Default date
var OutDate = time.Date(1970, time.January, 1, 12, 0, 0, 0, time.UTC)

// ArrayFromString Create array of values from separated string
func ArrayFromString(values string, separator string) []string {
	valuesArray := strings.Split(values, separator)
	if len(valuesArray) > 0 { // Remove empty string at the end
		if len(valuesArray[len(valuesArray)-1]) == 0 {
			valuesArray = valuesArray[:len(valuesArray)-1]
		}
	}
	return valuesArray
}

// ArrayToString Create separated string from array values
func ArrayToString(values []string, separator string) string {
	var out string
	for _, tag := range values {
		out += tag + separator
	}
	return out
}

// RemoveItem Remove item from slice at index
func RemoveItem(slice []string, index int) []string {
	slice[index] = slice[len(slice)-1] // Copy last element to index i.
	slice[len(slice)-1] = ""           // Erase last element (write zero value).
	return slice[:len(slice)-1]       // Truncate slice.
}

// HashPassword Create hash from password
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPasswordHash Check password hash
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// RandomKey Generate random key
func RandomKey(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// ContainsStr check value present in array
func ContainsStr(a []string, x string) bool {
    for _, n := range a {
        if x == n {
            return true
        }
    }
    return false
}

// ContainsInt check value present in array
func ContainsInt(a []uint, x uint) bool {
    for _, n := range a {
        if x == n {
            return true
        }
    }
    return false
}

// ContainsUint check value present in array
func ContainsUint(a []uint, x uint) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

// StringToDate Convert string to date
func StringToDate(date string, defaultVal time.Time) time.Time {
	if len(date) > 0 {
		val, err := time.Parse("2006-01-02", date)
		if err == nil {
			return val
		}
	}
	return defaultVal
}

// FormatDate Format date to string
func FormatDate(date time.Time) string {
	return date.Format("2006-01-02 15:04:05")
}

// GetHash Return hash of string
func GetHash(data []byte) string {
	h := sha1.New()
	h.Write(data)
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

// https://stackoverflow.com/a/30708914/2901140

// IsDirEmpty Check if directory is empty
func IsDirEmpty(name string) (bool, error) {
	f, err := os.Open(name)
	if err != nil {
		return false, err
	}
	defer f.Close()

	// read in ONLY one file
	_, err = f.Readdir(1)

	// and if the file is EOF... well, the dir is empty.
	if err == io.EOF {
		return true, nil
	}
	return false, err
}

// IsDirectory Is path directory
func IsDirectory(path string) (bool, error) {
    fileInfo, err := os.Stat(path)
    if err != nil{
      return false, err
    }
    return fileInfo.IsDir(), err
}

// FileExists Is file exists
func FileExists(filename string) bool {
    info, err := os.Stat(filename)
    if os.IsNotExist(err) {
        return false
    }
    return !info.IsDir()
}

// GetAvatar Form gravatar url from email
// Value may be the following: 404, mp, identicon, monsterid, wavatar, retro, robohash, blank
func GetAvatar(email string, d string) string {
	hasher := md5.New()
	hasher.Write([]byte(strings.TrimSpace(strings.ToLower(email))))
	return "https://gravatar.com/avatar/" + hex.EncodeToString(hasher.Sum(nil)) + "?d=" + d
}

// QueryParameterString Return query parameter or default value
func QueryParameterString(gc *gin.Context, name, defaultVal string) string {
	queryParameters := gc.Request.URL.Query()

	str := defaultVal
	if val, ok := queryParameters[name]; ok {
		if len(val) > 0 {
			str = val[0]
		}
	}
	return str
}

// QueryParameterInt Return query parameter as Int or default value
func QueryParameterInt(gc *gin.Context, name string, defaultVal int) int {
	queryParameters := gc.Request.URL.Query()

	str := defaultVal
	if val, ok := queryParameters[name]; ok {
		if len(val) > 0 {
			v, err := strconv.ParseInt(val[0], 0, 0)
			if err != nil {
				str = int(v)
			}
		}
	}
	return str
}
