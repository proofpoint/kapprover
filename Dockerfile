FROM       golang:1.12
ADD        . /go/src/github.com/proofpoint/kapprover
RUN        go install github.com/proofpoint/kapprover/cmd/kapprover && \
           go test github.com/proofpoint/kapprover/...

FROM debian:9.8-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --assume-yes \
                     # These packages are security updates
                     tzdata=2019a-0+deb9u1

COPY --from=0 /go/bin/kapprover .
ENTRYPOINT ["/kapprover"]
