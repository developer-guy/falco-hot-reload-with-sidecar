FROM ubuntu:18.04 as ubuntu

ARG FALCO_VERSION=0.28.0
ARG VERSION_BUCKET=bin

ENV FALCO_VERSION=${FALCO_VERSION}
ENV VERSION_BUCKET=${VERSION_BUCKET}

RUN apt-get -y update && apt-get -y install gridsite-clients curl

WORKDIR /

RUN curl -L -o falco.tar.gz \
    https://download.falco.org/packages/${VERSION_BUCKET}/x86_64/falco-$(urlencode ${FALCO_VERSION})-x86_64.tar.gz && \
    tar -xvf falco.tar.gz && \
    rm -f falco.tar.gz && \
    mv falco-${FALCO_VERSION}-x86_64 falco && \
    rm -rf /falco/usr/src/falco-* /falco/usr/bin/falco-driver-loader

RUN sed -e 's/time_format_iso_8601: false/time_format_iso_8601: true/' < /falco/etc/falco/falco.yaml > /falco/etc/falco/falco.yaml.new \
    && mv /falco/etc/falco/falco.yaml.new /falco/etc/falco/falco.yaml

FROM scratch as falcobinary

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

LABEL usage="docker run -i -t --privileged -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro --name NAME IMAGE"
# NOTE: for the "least privileged" use case, please refer to the official documentation

ENV HOST_ROOT /host
ENV HOME /root

COPY --from=ubuntu /falco /

CMD ["/usr/bin/falco", "-o", "time_format_iso_8601=true"]

FROM golang:1.16.3-alpine as gobuild

WORKDIR /falco-hot-reloader

ENV CGO_ENABLED=0 \
    GO111MODULE=on \
    GOOS=linux \
    GOARCH=amd64

COPY go.mod go.sum ./

RUN go mod download

COPY ./ ./

RUN go build -o falco-hot-reloader

FROM alpine:latest

WORKDIR /falco-hot-reloader

COPY --from=falcobinary /usr/bin/falco /usr/bin/falco
COPY --from=gobuild /falco-hot-reloader ./

RUN mkdir -p /usr/share/falco/lua

RUN mkdir -p /etc/falco

COPY --from=ubuntu /falco/usr/share/falco/lua /usr/share/falco/lua

COPY --from=ubuntu /falco/etc/falco/falco.yaml /etc/falco/falco.yaml

ENTRYPOINT ["./falco-hot-reloader"]
