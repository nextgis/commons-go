/*
 * File: util.go
 * Project: ngcommon
 * File Created: Tuesday, 26th May 2019 6:30:27 pm
 * Author: Dmitry Baryshnikov <dmitry.baryshnikov@nextgis.com>
 * -----
 * Last Modified: Sunday, 20th September 2020 1:04:44 am
 * Modified By: Dmitry Baryshnikov, <dmitry.baryshnikov@nextgis.com>
 * -----
 * Copyright 2019 - 2021 NextGIS, <info@nextgis.com>
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

package util

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nextgis/commons-go/context"
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
			if err == nil {
				str = int(v)
			}
		}
	}
	return str
}

// GetRemoteSmallFile Get remote data with timeout and write to file
func GetRemoteSmallFile(url, username, password string, addHeaders map[string]string, outPath string) (int, error) {
	b, code, err := GetRemoteBytes(url, username, password, addHeaders)
	if err != nil {
		return code, err
	}

	code = http.StatusCreated
	err = ioutil.WriteFile(outPath, b, 0644)
	if err != nil {
		code = http.StatusInternalServerError
	}
	return code, err
}

func setupRequest(req *http.Request, username, password string, addHeaders map[string]string) {
	if len(username) > 0 {
		if username == "access_token" {
			req.Header.Add("Authorization", password)
		} else {
			req.SetBasicAuth(username, password)
		}
	}
	for k, v := range addHeaders { 
		req.Header.Add(k, v)
	}
}

// GetRemoteBytes Get remote data with timeout
func GetRemoteBytes(url, username, password string, addHeaders map[string]string) ([]byte, int, error) {
	// https://medium.com/@nate510/don-t-use-go-s-default-http-client-4804cb19f779
	if gin.IsDebugging() {
		fmt.Printf("Get remote url: %s\n", url)
	}

	tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: context.BoolOption("HTTP_SKIP_SSL_VERIFY")},
    }
	var netClient = &http.Client{
		Transport: tr,
		Timeout: time.Second * time.Duration(context.IntOption("TIMEOUT")),
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	setupRequest(req, username, password, addHeaders)
	response, err := netClient.Do(req)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	defer response.Body.Close()

	// Sometimes get 204
	if response.StatusCode > 399 {
		return nil, response.StatusCode, fmt.Errorf("failed to get %s. Return status code is %d", url, response.StatusCode)
	}

	bodyBytes, err := ioutil.ReadAll(response.Body)

	if err != nil {
		return nil, response.StatusCode, err
	}

	return bodyBytes, http.StatusOK, nil
}

// PostRemoteBytes Post remote data with timeout
func PostRemoteBytes(url, username, password string, addHeaders map[string]string, data interface{}) ([]byte, int, error) {
	return sendRemoteBytes("POST", url, username, password, addHeaders, data)
}

// PutRemoteBytes Put remote data with timeout
func PutRemoteBytes(url, username, password string, addHeaders map[string]string, data interface{}) ([]byte, int, error) {
	return sendRemoteBytes("PUT", url, username, password, addHeaders, data)
}

func sendRemoteBytes(requestType, url, username, password string, addHeaders map[string]string, data interface{}) ([]byte, int, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: context.BoolOption("HTTP_SKIP_SSL_VERIFY")},
	}
	var netClient = &http.Client{
		Transport: tr,
		Timeout:   time.Second * time.Duration(context.IntOption("TIMEOUT")),
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	if gin.IsDebugging() {
		fmt.Printf("%s remote url: %s. Data %s\n", requestType,  url, jsonData)
	}

	req, err := http.NewRequest(requestType, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	setupRequest(req, username, password, addHeaders)
	req.Header.Set("Content-Type", "application/json")

	response, err := netClient.Do(req)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	defer response.Body.Close()

	// Sometimes get 204
	if response.StatusCode > 399 {
		return nil, response.StatusCode, fmt.Errorf("failed to send %s. Return status code is %d", url, response.StatusCode)
	}

	bodyBytes, err := ioutil.ReadAll(response.Body)

	if err != nil {
		return nil, response.StatusCode, err
	}

	return bodyBytes, http.StatusOK, nil
}

// IsZeroTime Check if time is not init
func IsZeroTime(t time.Time) bool {
	return t.Year() < 1000
}