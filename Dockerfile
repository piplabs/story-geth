# Build Geth in a stock Go builder container
FROM golang:1.23-alpine as builder

RUN apk add --no-cache gcc musl-dev linux-headers git

# Get dependencies - will also be cached if we won't change go.mod/go.sum
COPY go.mod /story-geth/
COPY go.sum /story-geth/
RUN cd /story-geth && go mod download

ADD . /story-geth
RUN cd /story-geth && go run build/ci.go install -static ./cmd/geth

# Pull Geth into a second stage deploy alpine container
FROM alpine:latest

RUN apk add --no-cache ca-certificates
COPY --from=builder /story-geth/build/bin/geth /usr/local/bin/

EXPOSE 8545 8546 30303 30303/udp

WORKDIR /root/.story/geth