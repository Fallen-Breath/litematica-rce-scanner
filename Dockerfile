FROM golang:1.26 AS build

WORKDIR /src

COPY go.mod ./
COPY cmd ./cmd

RUN CGO_ENABLED=0 go build -o /out/litematica-rce-scanner ./cmd/litematica-rce-scanner

FROM scratch

COPY --from=build /out/litematica-rce-scanner /litematica-rce-scanner

WORKDIR /scan
ENTRYPOINT ["/litematica-rce-scanner"]
CMD ["."]
