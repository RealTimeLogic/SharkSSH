projectName := 01-minimal-selib
transport := selib
exampleSources := 01-minimal/example.c

include $(dir $(abspath $(lastword $(MAKEFILE_LIST))))common.mk
