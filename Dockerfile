# Build Geth in a stock Go builder container
FROM golang:1.23-alpine as builder

# Add build arguments for metadata
ARG VERSION=unknown
ARG COMMIT=unknown
ARG BUILDNUM=unknown

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

# Create non-root user for security
RUN addgroup -g 1000 -S story && \
    adduser -u 1000 -S story -G story && \
    mkdir -p /home/story/.story/geth && \
    chown -R story:story /home/story

COPY --from=builder /story-geth/build/bin/geth /usr/local/bin/

# Add OCI standard labels for better container management
LABEL org.opencontainers.image.title="story-geth"
LABEL org.opencontainers.image.description="Story Protocol Geth Node"
LABEL org.opencontainers.image.source="https://github.com/piplabs/story-geth"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${COMMIT}"
LABEL org.opencontainers.image.vendor="Story Protocol"

EXPOSE 8545 8546 30303 30303/udp

# Switch to non-root user
USER story
WORKDIR /home/story/.story/geth

# Set default entrypoint for better container usage
ENTRYPOINT ["geth"]