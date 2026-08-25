projectName := 04-bas-sftp-sodisp
transport := sodisp
useBasDiskIo := 1
pluginSources := \
   BasIo/SharkSshBasIo.c \
   Shell/SharkSshShell.c \
   Sftp/SharkSshSftp.c
pluginIncludeDirs := BasIo Shell Sftp
exampleSources := \
   03-sftp/sftpService.c \
   03-sftp/sftpExample.c \
   04-bas-sftp/example.c
exampleIncludeDirs := 03-sftp 04-bas-sftp

include $(dir $(abspath $(lastword $(MAKEFILE_LIST))))common.mk
