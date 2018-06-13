LIB_PREFIX := lib
LIB_EXT := .a
G++ := g++
GCC := gcc
AR := ar
RM := rm
CP := cp
MKDIR := mkdir

SOURCES := $(wildcard src/*.cpp)
OBJS_FILENAMES := $(patsubst src/%.cpp,Obj/%.o,$(SOURCES))

COMMONPP_HOME := ../Common++
PACKETPP_HOME := ../Packet++
LIGHT_PCAPNG_PCPP_HOME := ../3rdParty/LightPcapNg
LIGHT_PCAPNG_HOME := $(LIGHT_PCAPNG_PCPP_HOME)/LightPcapNg

LIGHT_PCAPNG_SOURCES := $(wildcard $(LIGHT_PCAPNG_HOME)/src/*.c)
LIGHT_PCAPNG_OBJS_FILENAMES := $(patsubst $(LIGHT_PCAPNG_HOME)/src/%.c,$(LIGHT_PCAPNG_PCPP_HOME)/Obj/%.o,$(LIGHT_PCAPNG_SOURCES))


DEPS := -DLINUX

INCLUDES := -I"./src" \
			-I"./header" \
			-I"$(COMMONPP_HOME)/header" \
			-I"$(PACKETPP_HOME)/header" \
			-I"$(LIGHT_PCAPNG_HOME)/include"
			

INCLUDES += -I/usr/include/netinet



Obj/%.o: src/%.cpp
	@echo 'Building file: $<'
	@$(G++) $(DEPS) $(INCLUDES) $(FLAGS) -O2 -g -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:Obj/%.o=Obj/%.d)" -MT"$(@:Obj/%.o=Obj/%.d)" -o "$@" "$<"

CUR_TARGET := $(notdir $(shell pwd))

#.SILENT:

all: Pcap++.lib

start:
	@echo '==> Building target: $(CUR_TARGET)'

create-directories:
	@$(MKDIR) -p Obj
	@$(MKDIR) -p Lib

Pcap++.lib: start create-directories $(OBJS_FILENAMES)
	@cd $(LIGHT_PCAPNG_PCPP_HOME) && $(MAKE) light_pcapng_sources
	@$(AR) -r  "Lib/$(LIB_PREFIX)Pcap++$(LIB_EXT)" $(OBJS_FILENAMES) $(LIGHT_PCAPNG_OBJS_FILENAMES)
	@echo 'Finished successfully building: $(CUR_TARGET)'
	@echo ' '

clean:
	@cd $(LIGHT_PCAPNG_PCPP_HOME) && $(MAKE) clean
	@$(RM) -rf ./Obj/*
	@$(RM) -rf ./Lib/*
	@echo 'Clean finished: $(CUR_TARGET)'
