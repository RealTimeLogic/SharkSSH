projectName := 02-shell-sodisp
transport := sodisp
pluginSources := Shell/SharkSshShell.c
pluginIncludeDirs := Shell
exampleSources := 02-shell/shellExample.c 02-shell/example.c

include $(dir $(abspath $(lastword $(MAKEFILE_LIST))))common.mk
