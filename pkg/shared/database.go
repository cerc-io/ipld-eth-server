// VulcanizeDB
// Copyright © 2022 Vulcanize

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

import (
	"github.com/cerc-io/plugeth-statediff/indexer/database/sql/postgres"
	"github.com/jmoiron/sqlx"
)

// NewDB creates a new db connection and initializes the connection pool
func NewDB(connectString string, config postgres.Config) (*sqlx.DB, error) {
	db, connectErr := sqlx.Connect("postgres", connectString)
	if connectErr != nil {
		return nil, postgres.ErrDBConnectionFailed(connectErr)
	}
	if config.MaxConns > 0 {
		db.SetMaxOpenConns(config.MaxConns)
	}
	if config.MaxIdle > 0 {
		db.SetMaxIdleConns(config.MaxIdle)
	}
	if config.MaxConnLifetime > 0 {
		db.SetConnMaxLifetime(config.MaxConnLifetime)
	}

	return db, nil
}
