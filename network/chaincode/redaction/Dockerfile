# Chaincode-as-a-service image.
#
# The contract runs as its own container rather than being built by the peer
# through the Docker socket. That build path fails under Docker Desktop on
# Windows (the socket proxy closes mid-build), and running the contract as a
# service is what production Fabric deployments do in any case.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor/ vendor/
COPY *.go ./
RUN CGO_ENABLED=0 go build -mod=vendor -o /out/chaincode .

FROM alpine:3.20
COPY --from=build /out/chaincode /usr/local/bin/chaincode
# CHAINCODE_ID and CHAINCODE_SERVER_ADDRESS are supplied by compose; the peer
# matches the running service to an installed package by that id.
ENTRYPOINT ["/usr/local/bin/chaincode"]
