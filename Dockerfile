FROM busybox

MAINTAINER Bryce Kahle <bryce.kahle@mlssoccer.com>

RUN mkdir -p /etc/ssl/certs
ADD ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ADD go-ec2-security-group-presence /bin/ec2-security-group-presence

ENTRYPOINT ["/bin/ec2-security-group-presence"]
