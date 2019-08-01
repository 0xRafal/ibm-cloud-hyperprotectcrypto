
HOST_SYSTEM = $(shell uname | cut -f 1 -d_)
SYSTEM ?= $(HOST_SYSTEM)
CXX = g++
GCC = gcc

#flags for grpc. pkg-config can't be used in system with two GRPC lib installed
#CXXFLAGS += `pkg-config --cflags protobuf grpc`
CXXFLAGS += -pthread -I/usr/local/Cellar/protobuf/3.7.1/include -I/usr/local/Cellar/grpc/1.22.0/include \
	-I/usr/local/Cellar/c-ares/1.15.0/include -I/usr/local/openssl-1.1.1c/include -I../cxx
CXXFLAGS += -std=c++11 -g -O0

#flags for openssl engine
CFLAGS = -g -O0 -Wall -Iopenssl-1.1.1c/crypto -Iopenssl-1.1.1c/crypto/include -Iopenssl-1.1.1c/include -I/usr/local/openssl-1.1.1c/include

DEPFLAGS = -MMD -MP -MF build/$*.d

#pkg-config can't be used in system with two GRPC lib installed
#LDFLAGS += -L/usr/local/lib `pkg-config --libs protobuf grpc++ grpc`\
           -pthread\
           -ldl -lcurl -lcrypto         
LDFLAGS += -shared -L/usr/local/openssl-1.1.1c/lib -L/usr/local/Cellar/protobuf/3.7.1/lib -L/usr/local/Cellar/grpc/1.22.0/lib -L/usr/local/lib \
	-lprotobuf -pthread -lgrpc++ -lgrpc -pthread -ldl -lcurl -lcrypto

ifeq ($(SYSTEM),Darwin)
#shall use openssl 1.1.1c, not darwin default
#LDFLAGS += -lgrpc++_reflection\
           -L/usr/local/opt/openssl/lib

LDFLAGS += -lgrpc++_reflection
#CXXFLAGS += -I/usr/local/opt/openssl/include
else
    #...
endif

CXXSOURCES = grep11_api.cc util/credentials.cc $(wildcard grpc/*.cc)
OBJECTS = $(patsubst %.cc,build/%.o,$(CXXSOURCES))
CSOURCES = openssleng.c
OBJECTS += $(patsubst %.c,build/%.o,$(CSOURCES))
DEPS = $(patsubst %.o,build/%.d,$(OBJECTS))

all: build/libopenssleng.so

build/libopenssleng.so: $(OBJECTS)

	$(CXX) $^ $(LDFLAGS) $(DEPFLAGS) -o $@

build/%.o:	cxx/%.cc
	echo $(@D)
	mkdir -p $(@D)
	$(CXX) -c $(CXXFLAGS) $(DEPFLAGS) -o $@ $<

build/%.o:	%.cc
	echo $(@D)
	mkdir -p $(@D)
	$(CXX) -c $(CXXFLAGS) $(DEPFLAGS) -o $@ $<
	
build/%.o:	%.c
	echo $(@D)
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
	@rm -rdf cxx
include $(wildcard $(DEPS))

