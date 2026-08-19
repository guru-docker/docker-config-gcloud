FROM golang:1.26.5-alpine AS builder
ADD . /go/src/github.com/guru-docker/docker-config-gcloud
WORKDIR /go/src/github.com/guru-docker/docker-config-gcloud

RUN apk add --no-cache --virtual .build-deps gcc libc-dev
RUN go install --ldflags '-extldflags "-static"'
RUN apk del .build-deps

CMD ["/go/bin/docker-config-gcloud"]


FROM alpine

# The plugin talks TLS to cloudkms.googleapis.com, so the rootfs needs a trust
# store of its own; /run/gcloud is where the host directory holding credentials
# and ciphertext files is bind-mounted.
RUN apk update && apk add --no-cache ca-certificates
RUN mkdir -p /run/docker/plugins /run/gcloud

COPY --from=builder /go/bin/docker-config-gcloud .
CMD ["docker-config-gcloud"]
