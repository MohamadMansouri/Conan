LIB_PREFIX := lib
LIB_EXT := .a
G++ := g++
GCC := gcc
AR := ar
RM := rm
CP := cp
MKDIR := mkdir


SOURCES := $(wildcard src/*.cpp)
OBJS_FILENAMES_DEBUG := $(patsubst src/%.cpp,Obj/%.o,$(SOURCES))
OBJS_FILENAMES := $(filter-out Obj/debug_new.o,$(OBJS_FILENAMES_DEBUG))


DEPS := -DLINUX


INCLUDES := -I"./src" \
			-I"./header"

INCLUDES += -I/usr/include/netinet
			
Obj/%.o: src/%.cpp
	@echo 'Building file: $<'
	@$(G++) $(DEPS) $(INCLUDES) -O0 -g -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:Obj/%.o=Obj/%.d)" -MT"$(@:Obj/%.o=Obj/%.d)" -o "$@" "$<"

CUR_TARGET := $(notdir $(shell pwd))

#.SILENT:

all: start Common++.lib Common++.debug

start:
	@echo '==> Building target: $(CUR_TARGET)'

create-directories:
	@$(MKDIR) -p Obj
	@$(MKDIR) -p Lib
	@$(MKDIR) -p Lib/Debug
	@$(MKDIR) -p Lib/Release

Common++.lib: create-directories $(OBJS_FILENAMES)
	@$(AR) -r "Lib/Release/$(LIB_PREFIX)Common++$(LIB_EXT)" $(OBJS_FILENAMES)
	@echo 'Finished successfully building: $@'
	@echo ' '
	
Common++.debug: create-directories $(OBJS_FILENAMES_DEBUG)
	@$(AR) -r "Lib/Debug/$(LIB_PREFIX)Common++$(LIB_EXT)" $(OBJS_FILENAMES_DEBUG)
	@echo 'Finished successfully building: $@'
	@echo ' '

clean:
	@$(RM) -rf ./Obj/*
	@$(RM) -rf ./Lib/*
	@echo 'Clean finished: $(CUR_TARGET)'
