/*
 * File: lock_test.go
 * Project: ngcommon
 * File Created: Friday, 19th May 2023 4:11:23 pm
 * Author: Dmitry Baryshnikov <dmitry.baryshnikov@nextgis.com>
 * -----
 * Last Modified: Friday, 19th May 2023 4:11:34 pm
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
	"sync"
	"testing"
	"time"
)

func TestLockMultithreaded(t *testing.T) {
	var objectLockCache LockCache[uint]
	objectLockCache.Init()
	var wg1 sync.WaitGroup

	for i := 0; i < 2123; i++ {
		wg1.Add(1)
		go func(id int)  {
			objectLockCache.RLock(777, 1*time.Second)
			time.Sleep(5 * time.Millisecond)
			objectLockCache.RUnlock(777)

			wg1.Done()
		}(i)
	}
	wg1.Wait()

	for i := 0; i < 2212; i++ {
		wg1.Add(1)
		go func(id int)  {
			t.Logf("start objectLockCache %d", id)
			objectLockCache.Lock(777, 1*time.Second)
			t.Logf("lock objectLockCache %d", id)
			time.Sleep(8 * time.Millisecond)
			t.Logf("unlock objectLockCache %d", id)
			objectLockCache.Unlock(777)
			t.Logf("finish objectLockCache %d", id)

			wg1.Done()
		}(i)
	}
	wg1.Wait()

	objectLockCache.Free()
}