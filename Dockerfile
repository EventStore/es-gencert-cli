FROM golang:1.21-alpine AS build_base

RUN apk add --no-cache git

WORKDIR /tmp/es-gencert

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN GOEXPERIMENT=boringcrypto go build -o ./out/es-gencert-cli .

FROM alpine:3.9
RUN apk add ca-certificates bash

COPY --from=build_base /tmp/es-gencert/out/es-gencert-cli /app/es-gencert-cli

RUN adduser \
    --disabled-password \
    --gecos "" \
    --no-create-home \
    --uid "1000" \
    "eventstore" && \
    chown eventstore:eventstore /app \
    --recursive

USER eventstore
ENV PATH=$PATH:/app
WORKDIR /tmp
ENTRYPOINT ["/app/es-gencert-cli"]
CMD []
