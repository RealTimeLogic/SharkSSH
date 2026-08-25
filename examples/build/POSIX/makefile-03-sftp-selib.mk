projectName := 03-sftp-selib
transport := selib
pluginSources := Shell/SharkSshShell.c Sftp/SharkSshSftp.c
pluginIncludeDirs := Shell Sftp
exampleSources := \
   03-sftp/hostFileSystem.c \
   03-sftp/sftpService.c \
   03-sftp/sftpExample.c \
   03-sftp/example.c
exampleIncludeDirs := 03-sftp

include $(dir $(abspath $(lastword $(MAKEFILE_LIST))))common.mk
