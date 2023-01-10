/*
 * File: local.go
 * Project: ngcommon
 * File Created: Monday, 31st August 2019 2:07:35 am
 * Author: Dmitry Baryshnikov <dmitry.baryshnikov@nextgis.com>
 * -----
 * Last Modified: Sunday, 20th September 2020 1:03:41 am
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

import "github.com/nextgis/commons-go/context"

// LocalAuthInfo Local Info structure
type LocalAuthInfo struct {
	Enable      bool   `form:"enable" json:"enable"`             // LOCAL_LOGIN
	Log         bool   `form:"log" json:"log"`                   // LOG
	LogEdits    bool   `form:"log_edits" json:"log_edits"`       // LOG_ONLY_EDITS
	DefaultLang string `form:"default_lang" json:"default_lang"` // DEFAULT_LANGUAGE
	AdminGroup  string `form:"admin_group" json:"admin_group"`   // ADMIN_GROUP_NAME
}

// Fill Fill LocalAuthInfo structure by values
func (li *LocalAuthInfo) Fill() {
	li.Enable = context.BoolOption("LOCAL_LOGIN")
	li.Log = context.BoolOption("LOG")
	li.LogEdits = context.BoolOption("LOG_ONLY_EDITS")
	li.DefaultLang = context.StringOption("DEFAULT_LANGUAGE")
	li.AdminGroup = context.StringOption("ADMIN_GROUP_NAME")
}
