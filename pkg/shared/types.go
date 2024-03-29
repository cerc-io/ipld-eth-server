// VulcanizeDB
// Copyright © 2021 Vulcanize

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package shared

type PoolConfig struct {
	Enabled           bool
	HttpEndpoint      string
	PeerHttpEndpoints []string
}

type GroupConfig struct {
	CacheSizeInMB          int
	CacheExpiryInMins      int
	LogStatsIntervalInSecs int

	// Used in tests to override the cache name, to work around
	// the "duplicate registration of group" error from groupcache
	Name string
}

type GroupCacheConfig struct {
	Pool    PoolConfig
	StateDB GroupConfig
}
