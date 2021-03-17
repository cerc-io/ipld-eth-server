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

package events

import (
	"sync"
	"time"

	"github.com/lib/pq"
	log "github.com/sirupsen/logrus"
)

// Notifier listens to inserts on Postgres tables and forwards the data
type Notifier struct {
	listener *pq.Listener
	failed   chan error
}

// NewNotifier creates a new notifier for given PostgreSQL credentials.
func NewNotifier(connectStr, channelName string) (*Notifier, error) {
	n := &Notifier{failed: make(chan error, 2)}

	listener := pq.NewListener(
		connectStr,
		10*time.Second, time.Minute,
		n.callBack)

	if err := listener.Listen(channelName); err != nil {
		listener.Close()
		log.Println("ERROR!:", err)
		return nil, err
	}

	n.listener = listener
	return n, nil
}

// Notify is the main loop of the notifier to receive data from
// the database in JSON-FORMAT and send it down the provided channel.
func (n *Notifier) Notify(wg *sync.WaitGroup, outChan chan []byte, errChan chan error) {
	wg.Wait()
	go func() {
		defer wg.Done()
		for {
			select {
			case e := <-n.listener.Notify:
				if e == nil {
					continue
				}
				outChan <- []byte(e.Extra)
			case err := <-n.failed:
				if err != nil {
					errChan <- err
				}
				return
			case <-time.After(time.Minute):
				if err := n.listener.Ping(); err != nil {
					errChan <- err
					return
				}
			}
		}
	}()
}

// callBack
func (n *Notifier) callBack(event pq.ListenerEventType, err error) {
	if err != nil {
		log.Errorf("listener error: %s\n", err)
	}
	if event == pq.ListenerEventConnectionAttemptFailed {
		n.failed <- err
	}
	if event == pq.ListenerEventDisconnected {
		n.failed <- err
	}
}

// close closes the notifier.
func (n *Notifier) close() error {
	return n.listener.Close()
}
