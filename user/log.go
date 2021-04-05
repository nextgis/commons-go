/*
 * File: log.go
 * Project: ngcommon
 * File Created: Sunday, 24th January 2021 1:10:33 am
 * Author: Dmitry Baryshnikov <dmitry.baryshnikov@nextgis.com>
 * -----
 * Last Modified: Sunday, 24th January 2021 1:10:43 am
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

package users

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nextgis/commons-go/context"
)

// {
//     "@timestamp": "2005-08-09T18:31:42.201",
//     "request": {
//         "method": "GET",
//         "path": "/api/resource/",
//         "query_string": "?limit=10",
//         "remote_addr": "127.0.0.1"
//     },
//     "response": {
//         "status_code": 200,
//         "route_name": "resource.collection"
//     },
//     "user": {
//         "id": 1,
//         "keyname": "administrator",
//         "display_name": "Administrator",
//         "oauth_subject": "if-they-need-it”,
//     },
//     “fpdorder”: {
//         “id”: “some-uuid”,
//         “oauth_subject”: “some-other-uuid”
//     },
//     "context": {
//         "model": "qgis_vector_style",
//         "id":49
//     }
// }

type logRecord struct {
	TimeStamp time.Time      `json:"@timestamp"`
	Request   requestPart    `json:"request"`
	Response  responsePart   `json:"response"`
	User      *LogUserInfo    `json:"user"`
	Context   *LogContextInfo `json:"context"`
}

type requestPart struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	Query         string `json:"query_string"`
	RemoteAddress string `json:"remote_addr"`
}

type responsePart struct {
	StatusCode int    `json:"status_code"`
	RouteName  string `json:"route_name"`
}

// LogUserInfo User information struct
type LogUserInfo struct {
	ID          uint   `json:"id"`
	KeyName     string `json:"keyname"`
	DisplayName string `json:"display_name"`
	OAuthSubj   string `json:"oauth_subject"`
}

// LogContextInfo Context information struct
type LogContextInfo struct {
	ID    uint   `json:"id"`
	Model string `json:"model"`
}

func mapToString(mapData map[string][]string) string {
	if len(mapData) == 0 {
		return ""
	}
	outVal := "?"
	for k, v := range mapData {
		for _, vs := range v {
			if outVal != "?" {
				outVal += fmt.Sprintf("&%s=%s", k, vs)
			} else {
				outVal += fmt.Sprintf("%s=%s", k, vs)
			}
		}
	}
	return outVal
}

func logToStdout(gc *gin.Context, statusCode int, user *LogUserInfo,
	ctxInfo *LogContextInfo) {
	if !context.BoolOption("LOG") {
		return
	}
	requestMethod := gc.Request.Method
	if context.BoolOption("LOG_ONLY_EDITS") && requestMethod == "GET" {
		return
	}

	lr := logRecord{TimeStamp: time.Now().UTC()}
	// Request
	queryParameters := gc.Request.URL.Query()

	lr.Request.Method = requestMethod
	lr.Request.Path = gc.Request.URL.Path
	lr.Request.Query = mapToString(queryParameters)
	lr.Request.RemoteAddress = gc.ClientIP()

	// Response
	lr.Response.StatusCode = statusCode
	lr.Response.RouteName = gc.FullPath()

	// User
	lr.User = user

	// Context
	lr.Context = ctxInfo

	b, err := json.Marshal(lr)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(string(b))
	}
}

// OutputWithLog Form log reccord and finish route
func OutputWithLog(gc *gin.Context, statusCode int, user *LogUserInfo,
	ctxInfo *LogContextInfo, abort bool, obj interface{}) {
	logToStdout(gc, statusCode, user, ctxInfo)
	if abort {
		gc.AbortWithStatusJSON(statusCode, obj)
	} else {
		gc.JSON(statusCode, obj)
	}
}

// Log Write to log
func Log(gc *gin.Context, statusCode int, user *LogUserInfo, ctxInfo *LogContextInfo) {
	logToStdout(gc, statusCode, user, ctxInfo)
}
