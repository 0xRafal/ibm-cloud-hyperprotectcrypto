
HOST_SYSTEM = $(shell uname | cut -f 1 -d_)
SYSTEM ?= $(HOST_SYSTEM)
CXX = g++
GCC = gcc

#flags for grpc. pkg-config can't be used in system with two GRPC lib installed
#CXXFLAGS += `pkg-config --cflags protobuf grpc`

#CFLAGS for openssl engine
CFLAGS = -g -fPIC -O0 -Wall -Iopenssl-1.1.1c/crypto -Iopenssl-1.1.1c/crypto/include -Iopenssl-1.1.1c/include
CXXFLAGS += -pthread -std=c++11 -g -fPIC -O0 -I../cxx

ifeq ($(SYSTEM),Darwin)
CXXFLAGS += -I/usr/local/Cellar/protobuf/3.7.1/include -I/usr/local/Cellar/grpc/1.22.0/include \
	-I/usr/local/Cellar/c-ares/1.15.0/include -I/usr/local/openssl-1.1.1c/include -I../cxx
CFLAGS += -I/usr/local/openssl-1.1.1c/include

else
CXXFLAGS += -I/usr/include/google/protobuf -I/usr/local/include/grpc
#libc-ares-dev and libssl-dev header files are installed to /usr/include (default header)
endif

DEPFLAGS = -MMD -MP -MF build/$*.d

LDFLAGS += -shared -fPIC

ifeq ($(SYSTEM),Darwin)
LDFLAGS += -L/usr/local/openssl-1.1.1c/lib -L/usr/local/Cellar/protobuf/3.7.1/lib  -L/usr/local/lib \
	 /usr/local/Cellar/grpc/1.22.0/lib/libgrpc++.a /usr/local/Cellar/grpc/1.22.0/lib/libgrpc.a   /usr/local/openssl-1.1.1c/lib/libcrypto.a

else
#libssl-dev, libprotobuf10 library installed to /usr/lib/x86_64-linux-gnu (default lib)
    LDFLAGS += -lgrpc++ -lgrpc -l:libcrypto_NE.so.1.1 
endif

LDFLAGS += -lgrpc++_reflection -lprotobuf -pthread -ldl -lcurl

CXXSOURCES = grep11_api.cc util/credentials.cc $(wildcard grpc/*.cc)
OBJECTS = $(patsubst %.cc,build/%.o,$(CXXSOURCES))
CSOURCES = openssleng.c
OBJECTS += $(patsubst %.c,build/%.o,$(CSOURCES))
DEPS = $(patsubst %.o,%.d,$(OBJECTS))

all: build/libopenssleng.so

build/libopenssleng.so: $(OBJECTS)

	$(CXX) $^ $(LDFLAGS) $(DEPFLAGS) -o $@

build/%.o:	cxx/%.cc
	mkdir -p $(@D)
	$(CXX) -c $(CXXFLAGS) $(DEPFLAGS) -o $@ $<

build/%.o:	%.cc
	mkdir -p $(@D)
	$(CXX) -c $(CXXFLAGS) $(DEPFLAGS) -o $@ $<
	
build/%.o:	%.c
	mkdir -p $(@D)
	$(GCC) -c $(CFLAGS) $(DEPFLAGS) -o $@ $<
	
clean:
	rm -rf build util grpc
	
check:
	@echo "objects"
	@echo $(OBJECTS)
	@echo "c++ files:"
	@echo $(CXXSOURCES)
	@echo "c files:"
	@echo $(CSOURCES)
	@echo $(DEPS)
	@rm -rdf cxx
include $(wildcard $(DEPS))

