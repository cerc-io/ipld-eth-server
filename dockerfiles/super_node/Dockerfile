FROM golang:1.13-alpine as builder

RUN apk --update --no-cache add make git g++ linux-headers
# DEBUG
RUN apk add busybox-extras

# Get and build ipld-eth-server
ADD . /go/src/github.com/vulcanize/ipld-eth-server
WORKDIR /go/src/github.com/vulcanize/ipld-eth-server
RUN GO111MODULE=on GCO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o ipld-eth-server .

# Build migration tool
WORKDIR /
RUN go get -u -d github.com/pressly/goose/cmd/goose
WORKDIR /go/src/github.com/pressly/goose/cmd/goose
RUN GCO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -tags='no_mysql no_sqlite' -o goose .

WORKDIR /go/src/github.com/vulcanize/ipld-eth-server

# app container
FROM alpine

ARG USER
ARG CONFIG_FILE
ARG EXPOSE_PORT_1
ARG EXPOSE_PORT_2

RUN adduser -Du 5000 $USER
WORKDIR /app
RUN chown $USER /app
USER $USER

# chown first so dir is writable
# note: using $USER is merged, but not in the stable release yet
COPY --chown=5000:5000 --from=builder /go/src/github.com/vulcanize/ipld-eth-server/$CONFIG_FILE config.toml
COPY --chown=5000:5000 --from=builder /go/src/github.com/vulcanize/ipld-eth-server/dockerfiles/super_node/startup_script.sh .
COPY --chown=5000:5000 --from=builder /go/src/github.com/vulcanize/ipld-eth-server/dockerfiles/super_node/entrypoint.sh .


# keep binaries immutable
COPY --from=builder /go/src/github.com/vulcanize/ipld-eth-server/ipld-eth-server ipld-eth-server
COPY --from=builder /go/src/github.com/pressly/goose/cmd/goose/goose goose
COPY --from=builder /go/src/github.com/vulcanize/ipld-eth-server/db/migrations migrations/vulcanizedb
COPY --from=builder /go/src/github.com/vulcanize/ipld-eth-server/environments environments

EXPOSE $EXPOSE_PORT_1
EXPOSE $EXPOSE_PORT_2

ENTRYPOINT ["/app/startup_script.sh"]
