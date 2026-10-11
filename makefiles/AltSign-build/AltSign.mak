CC := clang
CXX := clang++

ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
include $(ROOT_DIR)/../main.mak

ALTSIGN_ROOT := $(UPSTREAM_DIR)/AltSign
ALTSIGN_NEWROOT := $(MAIN_DIR)/AltSign_patched
MINIZIP_ROOT := $(UPSTREAM_DIR)/AltSign/Dependencies/minizip
LDID_ROOT := $(UPSTREAM_DIR)/ldid
LDID_NEWROOT := $(MAIN_DIR)/ldid_patched

include $(MAIN_DIR)/makefiles/AltWindowsShim.mak

CFLAGS += -I$(ALTSIGN_ROOT) -I$(ALTSIGN_ROOT)/Dependencies -I$(MINIZIP_ROOT) -I$(LDID_ROOT) -mno-sse
#CFLAGS += -I$(ALTSIGN_ROOT) -I$(MINIZIP_ROOT) -I$(LDID_ROOT) -mno-sse
#CFLAGS += -DLDID_NOTOOLS # will lose some symbol if enable this

CXXFLAGS = $(CFLAGS) -std=c++17

# Build directly from the checked-in, known-working patched AltSign and ldid sources.
altsign_newfiles := $(wildcard $(ALTSIGN_NEWROOT)/*.*)
altsign_src := $(filter %.cpp,$(altsign_newfiles))

ldid_newfiles := $(LDID_NEWROOT)/ldid.cpp $(LDID_NEWROOT)/lookup2.c
ldid_src := $(ldid_newfiles)

preprocess :
.PHONY : preprocess

minizip_src := $(MINIZIP_ROOT)/ioapi.c $(MINIZIP_ROOT)/zip.c $(MINIZIP_ROOT)/unzip.c

objs += $(altsign_src:$(MAIN_DIR)/%=$(BUILD_DIR)/objs/%.o)
objs += $(ldid_src:$(MAIN_DIR)/%=$(BUILD_DIR)/objs/%.o)
objs += $(minizip_src:$(MAIN_DIR)/%=$(BUILD_DIR)/objs/%.o)

#ldid/%.o : CC := gcc
#ldid/%.o : CXX := g++

$(BUILD_DIR)/objs/%.c.o : $(BUILD_DIR)/%.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(EXTRA_FLAGS) -o $@ -c $<

$(BUILD_DIR)/objs/%.cpp.o : $(BUILD_DIR)/%.cpp
	mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(EXTRA_FLAGS) -o $@ -c $<

$(BUILD_DIR)/objs/%.c.o : $(MAIN_DIR)/%.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(EXTRA_FLAGS) -o $@ -c $<

$(BUILD_DIR)/objs/%.cpp.o : $(MAIN_DIR)/%.cpp
	mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(EXTRA_FLAGS) -o $@ -c $<

#python3 $(ROOT_DIR)/rewrite_altsign_source.py "$<" | $(CC) -x c -I`dirname $<` $(CFLAGS) $(EXTRA_FLAGS) -o $@ -c -
#python3 $(ROOT_DIR)/rewrite_altsign_source.py "$<" | $(CXX) -x c++ -I`dirname $<` $(CXXFLAGS) $(EXTRA_FLAGS) -o $@ -c -

$(BUILD_DIR)/AltSign.a : $(objs)
	ar rcs $@ $^

clean::
	rm -f $(objs) AltSign.a

all :: preprocess $(BUILD_DIR)/AltSign.a
.PHONY : all

.DEFAULT_GOAL := all
