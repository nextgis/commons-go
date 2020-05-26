package util

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

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

var infinityDate = time.Date(2100, time.January, 1, 12, 0, 0, 0, time.UTC)
var outDate = time.Date(1970, time.January, 1, 12, 0, 0, 0, time.UTC)

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
