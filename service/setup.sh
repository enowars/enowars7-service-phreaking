#!/bin/bash

cd src
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ../gnb cmd/gnb/main.go
rm -rf cmd/gnb
