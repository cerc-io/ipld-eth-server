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

package graphql

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

type BigInt big.Int

// ToInt converts b to a big.Int.
func (b *BigInt) ToInt() *big.Int {
	return (*big.Int)(b)
}

// String returns value of b as a decimal string.
func (b *BigInt) String() string {
	return b.ToInt().String()
}

// SetUint64 sets b to x and returns x.
func (b *BigInt) SetUint64(x uint64) *BigInt {
	var val big.Int
	val.SetUint64(x)
	*b = (BigInt)(val)
	return b
}

// MarshalText implements encoding.TextMarshaler
func (b BigInt) MarshalText() ([]byte, error) {
	return []byte(b.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler
func (b *BigInt) UnmarshalText(input []byte) error {
	raw, err := checkNumberText(input)
	if err != nil {
		return err
	}
	if len(raw) > 64 {
		return hexutil.ErrBig256Range
	}

	var val big.Int
	val.SetString(string(input[:]), 10)
	*b = (BigInt)(val)
	return nil
}

// ImplementsGraphQLType returns true if BigInt implements the provided GraphQL type.
func (b BigInt) ImplementsGraphQLType(name string) bool { return name == "BigInt" }

// UnmarshalGraphQL unmarshals the provided GraphQL query data.
func (b *BigInt) UnmarshalGraphQL(input interface{}) error {
	var err error
	switch input := input.(type) {
	case string:
		return b.UnmarshalText([]byte(input))
	case int32:
		var num big.Int
		num.SetInt64(int64(input))
		*b = BigInt(num)
	default:
		err = fmt.Errorf("unexpected type %T for BigInt", input)
	}
	return err
}

func checkNumberText(input []byte) (raw []byte, err error) {
	if len(input) == 0 {
		return nil, nil // empty strings are allowed
	}
	if len(input) > 1 && input[0] == '0' {
		return nil, hexutil.ErrLeadingZero
	}
	return input, nil
}
