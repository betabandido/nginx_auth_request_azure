# TODO: use multistage dockerfile (build + exec)

FROM golang:1.12-stretch
WORKDIR /go/src/github.com/betabandido/nginx_auth_request_azure
COPY . .
RUN go install

ENTRYPOINT ["/go/bin/nginx_auth_request_azure"]
