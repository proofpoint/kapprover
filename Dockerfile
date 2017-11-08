FROM       golang:1.9
ADD        . /go/src/github.com/proofpoint/kapprover
RUN        curl https://glide.sh/get | sh && \
           cd /go/src/github.com/proofpoint/kapprover && \
           glide install && \
           go install github.com/proofpoint/kapprover/cmd/kapprover

FROM debian:stretch
COPY --from=0 /go/bin/kapprover .
ENTRYPOINT ["/kapprover"]
