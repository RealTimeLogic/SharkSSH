# Shared POSIX build rules for the SharkSSH examples.

makefileDir := $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
sharkSshRoot := $(abspath $(makefileDir)/../../..)
sharkSslRoot ?= $(abspath $(sharkSshRoot)/../SharkSSL)
basRoot ?= $(abspath $(sharkSshRoot)/../BAS)

outputDir ?= $(makefileDir)obj
target := $(outputDir)/$(projectName)
objectDir := $(outputDir)/intermediate/$(projectName)

commonSources := \
   $(sharkSshRoot)/src/SharkSSH.c \
   $(sharkSshRoot)/src/SharkSshCrypto.c

sourceFiles := \
   $(commonSources) \
   $(addprefix $(sharkSshRoot)/src/plugins/,$(pluginSources)) \
   $(addprefix $(sharkSshRoot)/examples/,$(exampleSources))

includeDirs := \
   $(sharkSshRoot)/inc \
   $(sharkSshRoot)/examples/startup \
   $(addprefix $(sharkSshRoot)/src/plugins/,$(pluginIncludeDirs)) \
   $(addprefix $(sharkSshRoot)/examples/,$(exampleIncludeDirs))

ifeq ($(transport),selib)
sourceFiles += \
   $(sharkSslRoot)/src/SharkSSL.c \
   $(sharkSslRoot)/src/selib.c \
   $(sharkSshRoot)/examples/startup/selibStartup.c
includeDirs += \
   $(sharkSslRoot)/inc \
   $(sharkSslRoot)/inc/arch/Posix \
   $(sharkSslRoot)/src \
   $(sharkSslRoot)/src/arch/Posix
exampleCppFlags += -D_xprintf=printf
else ifeq ($(transport),sodisp)
sourceFiles += \
   $(basRoot)/src/BWS.c \
   $(basRoot)/src/arch/Posix/ThreadLib.c \
   $(basRoot)/src/arch/NET/generic/SoDisp.c \
   $(sharkSshRoot)/examples/startup/soDispStartup.c
includeDirs += \
   $(basRoot)/inc \
   $(basRoot)/inc/arch/Posix \
   $(basRoot)/inc/arch/NET/Posix
exampleCppFlags += -DSHARKSSH_SODISP_MAIN=1 -DXPRINTF=0
else
$(error transport must be selib or sodisp)
endif

ifeq ($(useBasDiskIo),1)
sourceFiles += $(basRoot)/src/DiskIo/posix/BaFile.c
endif

ifneq ($(words $(sourceFiles)),$(words $(sort $(notdir $(sourceFiles)))))
$(error source file base names must be unique within one example build)
endif

exampleCppFlags += $(addprefix -I,$(includeDirs))
CFLAGS ?= -O2
exampleCFlags := -Wall -fno-strict-aliasing -MMD -MP -pthread
exampleLdLibs := -pthread

objects := $(addprefix $(objectDir)/,$(notdir $(sourceFiles:.c=.o)))
dependencies := $(objects:.o=.d)

define compileSource
$(objectDir)/$(notdir $(1:.c=.o)): $(1) $(MAKEFILE_LIST)
	@mkdir -p $$(@D)
	$$(CC) $$(CPPFLAGS) $$(exampleCppFlags) $$(CFLAGS) $$(exampleCFlags) -c $$< -o $$@
endef

$(foreach source,$(sourceFiles),$(eval $(call compileSource,$(source))))

.DEFAULT_GOAL := all

all: $(target)

$(target): $(objects)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) $(exampleLdLibs)

run: $(target)
	$(target) $(args)

clean:
	rm -rf $(objectDir) $(target)

-include $(dependencies)

.PHONY: all clean run
