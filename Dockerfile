# syntax=docker/dockerfile:1

FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/abnormal-mcp ./cmd/abnormal-mcp

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/abnormal-mcp /abnormal-mcp
USER nonroot:nonroot
ENTRYPOINT ["/abnormal-mcp"]
CMD ["serve"]
