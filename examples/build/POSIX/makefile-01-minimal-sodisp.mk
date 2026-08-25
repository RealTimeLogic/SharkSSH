projectName := 01-minimal-sodisp
transport := sodisp
exampleSources := 01-minimal/example.c

include $(dir $(abspath $(lastword $(MAKEFILE_LIST))))common.mk
