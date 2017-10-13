all: build

# build ARM packages for Raspberry Pi
rpi:
	make all PLATFORM=arm


ifeq (${VERSION},)
  VERSION=$(shell git describe --tags)
endif
ifeq (${ARCH},)
  ARCH=$(shell uname -m)
endif
ifeq (${ARCH},x86_64)
  ARCH=amd64
endif
ifeq (${ARCH},armv7l) # beaglebone black
  ARCH=armhf
endif
ifeq (${ARCH},armv6l) # raspberry pi
  ARCH=armhf
endif

ifeq (${PLATFORM},arm)
  ARCH=armhf
endif

ifeq (${VERSION},)
  VERSION=$(shell git describe --tags)
endif
ifeq (${GITHASH},)
  GITHASH=$(shell git log -1 --format='%H')
endif
ifeq (${BUILDTIME},)
  BUILDTIME=$(shell date -u '+%Y-%m-%d %H:%M:%S')
endif

ifeq (${PLATFORM},arm)
  export GOOS=linux
  export GOARCH=arm
endif


.PHONY: version
version:
	@echo "  Version: ${VERSION}"
	@echo "  GitHash: ${GITHASH}"
	@echo "BuildTime: ${BUILDTIME}"

.PHONY: build
build: dep_ensure
	go build -o snmp-html -ldflags "-w -s -X 'main.Version=${VERSION}' -X 'main.GitHash=${GITHASH}' -X 'main.BuildTime=${BUILDTIME}'"

.PHONY: clean
clean:
	rm -f snmp-html


# vendoring
.PHONY: dep_ensure
${GOPATH}/bin/dep:
	go get -u github.com/golang/dep/cmd/dep
dep_ensure: ${GOPATH}/bin/dep
	${GOPATH}/bin/dep ensure
