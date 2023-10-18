FROM golang:1.21-alpine as debugger

# Include dlv
RUN go install github.com/go-delve/delve/cmd/dlv@latest

FROM golang:1.21-alpine as builder

RUN apk --update --no-cache add gcc musl-dev binutils-gold git

# Build ipld-eth-server
WORKDIR /go/src/github.com/cerc-io/ipld-eth-server

ARG GIT_VDBTO_TOKEN

# Cache the modules
ENV GO111MODULE=on
COPY go.mod .
COPY go.sum .
RUN if [ -n "$GIT_VDBTO_TOKEN" ]; then git config --global url."https://$GIT_VDBTO_TOKEN:@git.vdb.to/".insteadOf "https://git.vdb.to/"; fi && \
    go mod download && \
    rm -f ~/.gitconfig

COPY . .

# Build the binary
RUN GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o ipld-eth-server .

# app container
FROM alpine

RUN apk --update --no-cache add bash jq curl

ARG USER="vdm"
ARG CONFIG_FILE="./environments/example.toml"

RUN adduser -Du 5000 $USER
WORKDIR /app
RUN chown $USER /app
USER $USER

# chown first so dir is writable
# note: using $USER is merged, but not in the stable release yet
COPY --chown=5000:5000 --from=builder /go/src/github.com/cerc-io/ipld-eth-server/$CONFIG_FILE config.toml
COPY --chown=5000:5000 --from=builder /go/src/github.com/cerc-io/ipld-eth-server/entrypoint.sh .

RUN mkdir -p nitro-data && chown -R 5000:5000 nitro-data

# keep binaries immutable
COPY --from=builder /go/src/github.com/cerc-io/ipld-eth-server/ipld-eth-server ipld-eth-server
COPY --from=builder /go/src/github.com/cerc-io/ipld-eth-server/environments environments

# Allow for debugging
COPY --from=debugger  /go/bin/dlv /usr/local/bin/

ENTRYPOINT ["/app/entrypoint.sh"]
