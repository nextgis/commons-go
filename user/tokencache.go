/*
 * File: tokencache.go
 * Project: ngcommon
 * File Created: Thursday, 5th November 2020 4:40:57 pm
 * Author: Dmitry Baryshnikov <dmitry.baryshnikov@nextgis.com>
 * -----
 * Last Modified: Thursday, 5th November 2020 4:42:03 pm
 * Modified By: Dmitry Baryshnikov, <dmitry.baryshnikov@nextgis.com>
 * -----
 * Copyright 2019 - 2020 NextGIS, <info@nextgis.com>
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
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/nextgis/commons-go/context"
)

var tokenCache *lru.Cache

// InitTokenCache Initialise token cache
func InitTokenCache() error {
	maxCacheSize := context.IntOption("TOKEN_CACHE_SIZE")
	uc, err := lru.New(maxCacheSize)
	if err == nil {
		tokenCache = uc
	}
	return err
}
 
// TokenInfo token info
type TokenInfo struct {
	Exp    time.Time
	UserID uint
}

// GetFromTokenCache Get value from token cache
func GetFromTokenCache(key interface{}) (value TokenInfo, ok bool)  {
	val, ok := tokenCache.Get(key)
	return val.(TokenInfo), ok
}

// RemoveFromTokenCache Remove token from cache
func RemoveFromTokenCache(key interface{}) {
	tokenCache.Remove(key)
}

// AddToTokenCache Add value to token cache
func AddToTokenCache(key, value TokenInfo) (bool) {
	return tokenCache.Add(key, value)
}
