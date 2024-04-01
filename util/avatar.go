/*
 * File: avata.go
 * Project: ngcommon
 * File Created: Sunday, 28th November 2021 6:13:30 pm
 * Author: Dmitry Baryshnikov <dmitry.baryshnikov@nextgis.com>
 * -----
 * Last Modified: Sunday, 28th November 2021 6:13:45 pm
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
	"crypto/md5"
	"encoding/hex"
	"image/color"
	"image/png"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/nextgis/commons-go/avatar"
	"github.com/nextgis/commons-go/context"
)

// GetAvatar return avatar png bytes
func GetAvatar(name, login, email string, size int, palette []color.Color, 
	random bool) []byte {
	var data []byte
	code := http.StatusNotFound
	var err error
	if len(email) > 0 {
		url := getGravatarURL(email, "404")
		data, code, err = GetRemoteBytes(url, "", "", map[string]string{}, nil)
	}
	if err != nil || code == http.StatusNotFound {		
		name = strings.TrimSpace(name)
		firstRune, _ := utf8.DecodeRuneInString(name)
		if !isHan(firstRune) && !unicode.IsLetter(firstRune) {
			name = strings.TrimSpace(login)
			firstRune, _ = utf8.DecodeRuneInString(name)
			if !isHan(firstRune) && !unicode.IsLetter(firstRune) {
				name = strings.TrimSpace(email)
				firstRune, _ = utf8.DecodeRuneInString(name)
				if !isHan(firstRune) && !unicode.IsLetter(firstRune) {
					name = "Guest"
					firstRune, _ = utf8.DecodeRuneInString(name)
				}
			}
		}

		opt := letteravatar.Options{}
		if len(palette) > 0 {
			opt.Palette = palette
		}
		if !random {
			opt.PaletteKey = name
		}

		// https://github.yuuza.net/disintegration/letteravatar
		img, err := letteravatar.Draw(size, firstRune, &opt)
		if err != nil {
			context.CaptureException(err, gin.IsDebugging())
			return nil
		}

		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			context.CaptureException(err, gin.IsDebugging())
			return nil
		}
		
		return buf.Bytes()
	}
	return data
}

// Is it Chinese characters?
func isHan(r rune) bool {
	return unicode.Is(unicode.Scripts["Han"], r) 
}

func getGravatarURL(email string, d string) string {
	hasher := md5.New()
	hasher.Write([]byte(strings.TrimSpace(strings.ToLower(email))))
	return "https://gravatar.com/avatar/" + hex.EncodeToString(hasher.Sum(nil)) + "?d=" + d
}