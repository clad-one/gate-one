FROM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg

RUN CGO_ENABLED=0 go build -o /out/gate-one ./cmd/gate-one \
 && CGO_ENABLED=0 go build -o /out/cladone-auth ./cmd/cladone-auth \
 && CGO_ENABLED=0 go build -o /out/fake-google ./cmd/fake-google

FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=build /out/ /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/gate-one"]
