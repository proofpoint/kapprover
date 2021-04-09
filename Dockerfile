FROM       golang:1.15.6
WORKDIR    /go/src/github.com/proofpoint/kapprover
ADD        . .
RUN        go install -mod vendor -a ./cmd/kapprover && \
           go test -mod vendor ./...

FROM gcr.io/distroless/base-debian10:nonroot

COPY --from=0 /go/bin/kapprover /
ENTRYPOINT ["/kapprover"]
