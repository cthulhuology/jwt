PROJECT = jwt
PROJECT_DESCRIPTION = minimal jwt for erlang
PROJECT_VERSION = 0.1.0

include erlang.mk

.PHONY: keys
keys:
	openssl genrsa -out private.pem 2048
	openssl rsa -in private.pem -outform PEM -pubout -out public.pem


