prefix ?= /usr/local

.PHONY: build install all

all: build

build:
	xcodebuild -project "./WBBlades.xcodeproj" -target "WBBlades" -configuration Release

install: build
	mkdir -p $(prefix)/bin
	install -c build/Release/blades $(prefix)/bin/
