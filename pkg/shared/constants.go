// VulcanizeDB
// Copyright © 2019 Vulcanize

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

const (
	DefaultMaxBatchSize   uint64 = 100
	DefaultMaxBatchNumber int64  = 50

	GcachePoolEnabled             = "GCACHE_POOL_ENABLED"
	GcachePoolHttpPath            = "GCACHE_POOL_HTTP_PATH"
	GcachePoolHttpPeers           = "GCACHE_POOL_HTTP_PEERS"
	GcacheStatedbCacheSize        = "GCACHE_STATEDB_CACHE_SIZE"
	GcacheStatedbCacheExpiry      = "GCACHE_STATEDB_CACHE_EXPIRY"
	GcacheStatedbLogStatsInterval = "GCACHE_STATEDB_LOG_STATS_INTERVAL"
)
