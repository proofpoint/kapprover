FROM       golang:1.13.4
ADD        . /go/src/github.com/proofpoint/kapprover
RUN        go install github.com/proofpoint/kapprover/cmd/kapprover && \
           go test github.com/proofpoint/kapprover/...

FROM debian:10.0-slim

COPY --from=0 /go/bin/kapprover .
ENTRYPOINT ["/kapprover"]
