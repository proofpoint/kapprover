FROM       golang:1.10
ADD        . /go/src/github.com/proofpoint/kapprover
RUN        go install github.com/proofpoint/kapprover/cmd/kapprover && \
           go test github.com/proofpoint/kapprover/...

FROM debian:stretch
COPY --from=0 /go/bin/kapprover .
ENTRYPOINT ["/kapprover"]
