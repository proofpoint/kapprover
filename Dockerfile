FROM       golang:1.15.6
ADD        . /go/src/github.com/proofpoint/kapprover
RUN        go install github.com/proofpoint/kapprover/cmd/kapprover && \
           go test github.com/proofpoint/kapprover/...

FROM gcr.io/distroless/base-debian10

COPY --from=0 /go/bin/kapprover .
ENTRYPOINT ["/kapprover"]
