GHACCOUNT := hooklift
NAME := gowsdl
VERSION := v0.2.2

include common.mk

deps:
	go get github.com/c4milo/github-release
	go get github.com/mitchellh/gox
	go get github.com/hooklift/assert
