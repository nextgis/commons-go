/*
 * File: acl.go
 * Project: ngcommon
 * File Created: Tuesday, 10th January 2023 3:07:46 pm
 * Author: Dmitry Baryshnikov <dmitry.baryshnikov@nextgis.com>
 * -----
 * Last Modified: Tuesday, 10th January 2023 3:07:50 pm
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

package users

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/nextgis/commons-go/context"
)

// IsCookieAuth Check if this is cookie based authentication
func IsCookieAuth(gc *gin.Context) bool {
	session := context.DefaultSession(gc)
	user := session.Get("user")
	return user != nil
}

// IsBasicAuth Check if this is basic authentication
func IsBasicAuth(gc *gin.Context) bool {
	auth := strings.SplitN(gc.Request.Header.Get("Authorization"), " ", 2)
	if len(auth) == 2 && auth[0] == "Basic" {
		return true
	}

	return true
}

// IsAPIKeyAuth Check if this is API key authentication
func IsAPIKeyAuth(gc *gin.Context) bool {
	apikey := gc.Query("apikey")
	return len(apikey) > 0
}

// IsOAuth2 Check if this is OAth2 authentication
func IsOAuth2(gc *gin.Context) bool {
	// Check header
	auth := strings.SplitN(gc.Request.Header.Get("Authorization"), " ", 2)
	if len(auth) > 1 && auth[0] == "Bearer" {
		return true
	}

	// Check session
	session := context.DefaultSession(gc)
	isOAuth := session.Get("oauth")
	return isOAuth != nil && isOAuth.(bool)
}

// AuthenticationRequired check if authenticate required
func AuthenticationRequired() gin.HandlerFunc {
	return func(gc *gin.Context) {
		if IsAPIKeyAuth(gc) || IsCookieAuth(gc) || IsBasicAuth(gc) || IsOAuth2(gc) {
			gc.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{"error": "User needs to be signed in to access this service"})
			return
		}
		gc.Next()
	}
}