FROM golang:1.26 AS build

WORKDIR /src

COPY go.mod ./
COPY cmd ./cmd

RUN CGO_ENABLED=0 go build -o /out/litematica-rce-scanner ./cmd/litematica-rce-scanner

FROM gcr.io/distroless/static-debian13

COPY --from=build /out/litematica-rce-scanner /usr/local/bin/litematica-rce-scanner

WORKDIR /scan
ENTRYPOINT ["/usr/local/bin/litematica-rce-scanner"]
CMD ["."]
