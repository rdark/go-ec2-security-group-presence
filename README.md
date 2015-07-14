go-ec2-security-group-presence
==============================

Presence sidekick to add a security group to an instance


## Build Instructions

    $ go get .
    $ CGO_ENABLED=0 GOOS=linux go build -a -tags netgo -ldflags '-w' .
    $ docker build --rm -t $tag_name .
