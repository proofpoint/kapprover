FROM       golang:1.9
ADD        . /go/src/github.com/coreos/kapprover
RUN        curl https://glide.sh/get | sh && \
           cd /go/src/github.com/coreos/kapprover && \
           glide install && \
           go install github.com/coreos/kapprover/cmd/kapprover

FROM debian:stretch
COPY --from=0 /go/bin/kapprover .
ENTRYPOINT ["/kapprover"]
