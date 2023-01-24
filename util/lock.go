/*
 * File: lock.go
 * Project: ngcommon
 * File Created: Wednesday, 28th December 2022 5:59:40 pm
 * Author: Dmitry Baryshnikov <dmitry.baryshnikov@nextgis.com>
 * -----
 * Last Modified: Wednesday, 28th December 2022 5:59:48 pm
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

package util

import (
	"sync"
	"time"

	"github.com/nextgis/commons-go/context"
)

// LockMutex lock mutex with expiration
type LockMutex struct {
	locker sync.Mutex
	expire time.Time
	isLocked bool
}

func (lm *LockMutex) lock(exp time.Time) {
	lm.locker.Lock()
	lm.isLocked = true
	lm.expire = exp
}

func (lm *LockMutex) unlock() {
	if lm.isLocked {
		lm.locker.Unlock()
	}
	lm.isLocked = false
}

func (lm *LockMutex) trylock(exp time.Time) bool {
	if lm.locker.TryLock() {
		lm.isLocked = true
		lm.expire = exp
		return true
	}
	return false
}

// LockCache lock cache with expire support
type LockCache[K comparable] struct {
	locker sync.RWMutex
	data   map[K]*LockMutex
}

// Init init lock cache
func (lc *LockCache[K]) Init() {
	lc.locker.Lock()
	defer lc.locker.Unlock()
	lc.data = make(map[K]*LockMutex)
}

// Get get lock mutex
func (lc *LockCache[K]) Get(key K) (m *LockMutex, ok bool) {
	lc.locker.RLock()
	defer lc.locker.RUnlock()

	m, ok = lc.data[key]
	return
}

// Set set lock mutex
func (lc *LockCache[K]) Set(key K, m *LockMutex) {
	lc.locker.Lock()
	defer lc.locker.Unlock()

	lc.data[key] = m
}

// Free free unused resources
func (lc *LockCache[K]) Free() {
	lc.locker.RLock()
	defer lc.locker.RUnlock()

	now := time.Now()

	for k, v := range lc.data {
		if v.expire.Before(now) {
			v.unlock()
			delete(lc.data, k)
		}
	}
}

// TryLock try to lock by key
func (lc *LockCache[K]) TryLock(key K, duration time.Duration) bool {
	if duration.Seconds() < 1 {
		duration = time.Second * time.Duration(context.IntOption("TIMEOUT")*5)
	}
	t := time.Now().Add(duration)
	if val, ok := lc.Get(key); ok {
		if ret := val.trylock(t); ret {
			return true
		}
		return false
	}

	m := &LockMutex{
		locker: sync.Mutex{},
		expire: t,
	}
	m.lock(t)

	lc.Set(key, m)
	return true
}

// Unlock unlock by key
func (lc *LockCache[K]) Unlock(key K) {
	if val, ok := lc.Get(key); ok {
		val.unlock()
	}
}

// Lock lock by key
func (lc *LockCache[K]) Lock(key K, duration time.Duration) {
	if duration.Seconds() < 1 {
		duration = time.Second * time.Duration(context.IntOption("TIMEOUT")*5)
	}
	t := time.Now().Add(duration)
	if val, ok := lc.Get(key); ok {
		val.lock(t)
	} else {
		m := &LockMutex{
			locker: sync.Mutex{},
			expire: t,
		}

		lc.Set(key, m)
		m.lock(t)
	}
}
