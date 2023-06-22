/*
 * File: lock.go
 * Project: ngcommon
 * File Created: Wednesday, 28th December 2022 5:59:40 pm
 * Author: Dmitry Baryshnikov <dmitry.baryshnikov@nextgis.com>
 * -----
 * Last Modified: Wednesday, 28th December 2022 5:59:48 pm
 * Modified By: Dmitry Baryshnikov, <dmitry.baryshnikov@nextgis.com>
 * -----
 * Copyright 2019-2023 NextGIS, <info@nextgis.com>
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
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nextgis/commons-go/context"
)

const mutexLocked = 1

// LockMutex lock mutex with expiration
type LockMutex struct {
	locker sync.RWMutex
	expire time.Time
}

func (lm *LockMutex) lock(exp time.Time) {
	lm.locker.Lock()
	lm.expire = exp
}

func (lm *LockMutex) unlock() {
	if lm.isLocked() {
		lm.locker.Unlock()
	}
}

func (lm *LockMutex) isLocked() bool {
	state := reflect.ValueOf(&lm.locker).Elem().FieldByName("w").FieldByName("state")
	return state.Int()&mutexLocked == mutexLocked

}

// https://github.com/trailofbits/go-mutexasserts
func readerCount(rw *sync.RWMutex) int64 {
	// Look up the address of the readerCount field and use it to create a pointer to an atomic.Int32,
	// then load the value to return.
	rc := (*atomic.Int32)(reflect.ValueOf(rw).Elem().FieldByName("readerCount").Addr().UnsafePointer())
	return int64(rc.Load())
}

func (lm *LockMutex) isRLocked() bool {
	return readerCount(&lm.locker) > 0
}

func (lm *LockMutex) trylock(exp time.Time) bool {
	if lm.locker.TryLock() {
		lm.expire = exp
		return true
	}
	return false
}


func (lm *LockMutex) rlock(exp time.Time) {
	lm.locker.RLock()
	lm.expire = exp
}

func (lm *LockMutex) runlock() {
	if lm.isRLocked() {
		lm.locker.RUnlock()
	}
}

func (lm *LockMutex) tryRlock(exp time.Time) bool {
	if lm.locker.TryRLock() {
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
	lc.data = make(map[K]*LockMutex)
	lc.locker.Unlock()
}

// Get get lock mutex
func (lc *LockCache[K]) Get(key K) (m *LockMutex, ok bool) {
	lc.locker.RLock()
	m, ok = lc.data[key]
	lc.locker.RUnlock()
	return
}

// Set set lock mutex
func (lc *LockCache[K]) Set(key K, m *LockMutex) {
	lc.locker.Lock()
	lc.data[key] = m
	lc.locker.Unlock()
}

// Free free unused resources
func (lc *LockCache[K]) Free() {
	if !lc.locker.TryLock() {
		return
	}

	now := time.Now()

	for k, v := range lc.data {
		if v.expire.Before(now) {
			// isLocked := v.isLocked
			v.unlock()
			// if !isLocked {
				delete(lc.data, k)
			// }
		}
	}
	lc.locker.Unlock()
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
		locker: sync.RWMutex{},
		expire: t,
	}

	m.lock(t)
	lc.Set(key, m)
	return true
}


// TryRLock try to rlock by key
func (lc *LockCache[K]) TryRLock(key K, duration time.Duration) bool {
	if duration.Seconds() < 1 {
		duration = time.Second * time.Duration(context.IntOption("TIMEOUT")*5)
	}
	t := time.Now().Add(duration)

	if val, ok := lc.Get(key); ok {
		if ret := val.tryRlock(t); ret {
			return true
		}
		return false
	}

	m := &LockMutex{
		locker: sync.RWMutex{},
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

// RUnlock unlock read mutex by key
func (lc *LockCache[K]) RUnlock(key K) {
	if val, ok := lc.Get(key); ok {
		val.runlock()
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
			locker:   sync.RWMutex{},
		}

		m.lock(t)
		lc.Set(key, m)
	}
}


// Lock lock by key
func (lc *LockCache[K]) RLock(key K, duration time.Duration) {
	if duration.Seconds() < 1 {
		duration = time.Second * time.Duration(context.IntOption("TIMEOUT")*5)
	}
	t := time.Now().Add(duration)

	if val, ok := lc.Get(key); ok {
		val.rlock(t)
	} else {
		m := &LockMutex{
			locker:   sync.RWMutex{},
		}

		m.rlock(t)
		lc.Set(key, m)
	}
}
