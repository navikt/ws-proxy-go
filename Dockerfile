FROM cgr.dev/chainguard/go:latest AS builder
ARG APP
ENV GOOS=linux
ENV CGO_ENABLED=0
ENV GO111MODULE=on
COPY . /src
WORKDIR /src
RUN go mod download
RUN go build -a -installsuffix cgo -o /bin/ws-proxy-go main.go

FROM cgr.dev/chainguard/static:latest
COPY --from=builder /bin/ws-proxy-go /app/ws-proxy-go
ENTRYPOINT ["/app/ws-proxy-go"]