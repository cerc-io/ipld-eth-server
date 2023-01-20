// VulcanizeDB
// Copyright © 2020 Vulcanize

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

package prom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cerc-io/ipld-eth-server/v4/pkg/log"
	"github.com/google/uuid"

	"github.com/ethereum/go-ethereum/rpc"
)

const (
	jsonMethod               = "method"
	jsonParams               = "params"
	jsonReqId                = "id"
	headerUserId             = "X-User-Id"
	headerOriginalRemoteAddr = "X-Original-Remote-Addr"
)

// Peek at the request and update the Context accordingly (eg, API method, user ID, etc.)
func prepareRequest(r *http.Request) (*http.Request, error) {
	// Generate a unique ID for this request.
	uniqId, err := uuid.NewUUID()
	if nil != err {
		log.Error("Error generating ID: ", err)
		return nil, err
	}

	// Read the body so that we can peek inside.
	body, err := io.ReadAll(r.Body)
	if nil != err {
		log.Error("Error reading request body: ", err)
		return nil, err
	}

	// Replace it with a re-readable copy.
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	// All API requests should be JSON.
	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if nil != err {
		log.Error("Error parsing request body: ", err)
		return nil, err
	}

	// Pull out the method name, request ID, user ID, and address info.
	reqId := fmt.Sprintf("%g", result[jsonReqId])
	reqMethod := fmt.Sprintf("%v", result[jsonMethod])
	reqParams := fmt.Sprintf("%v", result[jsonParams])
	// Truncate parameters unless trace logging is enabled.
	if !log.IsLevelEnabled(log.TraceLevel) {
		if len(reqParams) > 250 {
			reqParams = reqParams[:250] + "..."
		}
	}
	userId := r.Header.Get(headerUserId)
	conn := r.Header.Get(headerOriginalRemoteAddr)
	if len(conn) == 0 {
		conn = r.RemoteAddr
	}

	// Add it all to the request context.
	ctx := r.Context()
	ctx = context.WithValue(ctx, log.CtxKeyUniqId, uniqId.String())
	ctx = context.WithValue(ctx, log.CtxKeyApiMethod, reqMethod)
	ctx = context.WithValue(ctx, log.CtxKeyApiParams, string(reqParams))
	ctx = context.WithValue(ctx, log.CtxKeyApiReqId, reqId)
	ctx = context.WithValue(ctx, log.CtxKeyUserId, userId)
	ctx = context.WithValue(ctx, log.CtxKeyConn, conn)

	return r.WithContext(ctx), nil
}

// HTTPMiddleware http connection metric reader
func HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		r, err := prepareRequest(r)
		if nil != err {
			w.WriteHeader(400)
			return
		}
		ctx := r.Context()
		apiMethod := fmt.Sprintf("%s", ctx.Value(log.CtxKeyApiMethod))

		if metrics {
			httpCount.WithLabelValues(apiMethod).Inc()
		}

		log.Debugx(ctx, "START")
		next.ServeHTTP(w, r)
		duration := time.Now().Sub(start)
		log.Debugxf(context.WithValue(ctx, log.CtxKeyDuration, duration.Milliseconds()), "END")

		if metrics {
			httpDuration.WithLabelValues(apiMethod).Observe(duration.Seconds())
		}
	})
}

// WSMiddleware websocket connection counter
func WSMiddleware(next http.Handler) http.Handler {
	if !metrics {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wsCount.Inc()
		next.ServeHTTP(w, r)
		wsCount.Dec()
	})
}

// IPCMiddleware unix-socket connection counter
func IPCMiddleware(server *rpc.Server, client rpc.Conn) {
	if metrics {
		ipcCount.Inc()
	}
	server.ServeCodec(rpc.NewCodec(client), 0)
	if metrics {
		ipcCount.Dec()
	}
}
