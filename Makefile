# includes
PCAPPP_INCLUDES := -I./Dist/header -I/usr/include/netinet

# libs dir
PCAPPP_LIBS_DIR := -L./Dist

# libs
PCAPPP_LIBS := -lPcap++ -lPacket++ -lCommon++ -lpcap -lpthread

# build flags
PCAPPP_BUILD_FLAGS :=

COMMONPP_HOME:= ./Common++
PACKETPP_HOME:=./Packet++
PCAPPP_HOME:=./Pcap++

LIB_PREFIX := lib
LIB_EXT := .a
G++ := g++
GCC := gcc
AR := ar
RM := rm
CP := cp
MKDIR := mkdir

SOURCES := $(wildcard *.cpp)
OBJS_FILENAMES := $(patsubst %.cpp,Obj/%.o,$(SOURCES))

Obj/%.o: %.cpp
	@echo 'Building file: $<'
	@$(G++) $(PCAPPP_INCLUDES) -O2 -g -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:Obj/%.o=Obj/%.d)" -MT"$(@:Obj/%.o=Obj/%.d)" -o "$@" "$<"


UNAME := $(shell uname)
CUR_TARGET := $(notdir $(shell pwd))

.SILENT:

all:  dependents conan

start:
	@echo '==> Building target: $(CUR_TARGET)'

dependents:
	@cd $(COMMONPP_HOME)             && $(MAKE) all
	@cd $(PACKETPP_HOME)             && $(MAKE) all
	@cd $(PCAPPP_HOME)               && $(MAKE) all
	@$(MKDIR) -p Dist
	@$(MKDIR) -p Dist/header
	@$(CP) $(COMMONPP_HOME)/Lib/Release/* ./Dist
	@$(CP) $(PACKETPP_HOME)/Lib/* ./Dist
	@$(CP) $(PCAPPP_HOME)/Lib/* ./Dist
	@$(CP) $(COMMONPP_HOME)/header/* ./Dist/header
	@$(CP) $(PACKETPP_HOME)/header/* ./Dist/header
	@$(CP) $(PCAPPP_HOME)/header/* ./Dist/header
	@echo 'Finished successfully building PcapPlusPlus libs'
	@echo ' '

create-directories:
	@$(MKDIR) -p Obj
	@$(MKDIR) -p Bin


conan: start create-directories $(OBJS_FILENAMES)
	@$(G++) $(PCAPPP_LIBS_DIR) $(PCAPPP_BUILD_FLAGS) -o "./Bin/conan" $(OBJS_FILENAMES) $(PCAPPP_LIBS)
	@echo 'Finished successfully building: $(CUR_TARGET)'
	@echo ' '


clean:
	@$(RM) -rf ./Obj/*
	@$(RM) -rf ./Bin/*
	@cd $(COMMONPP_HOME)             && $(MAKE) clean
	@cd $(PACKETPP_HOME)             && $(MAKE) clean
	@cd $(PCAPPP_HOME)               && $(MAKE) clean
	@echo 'Clean finished: $(CUR_TARGET)'