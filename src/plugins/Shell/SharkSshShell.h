/* Bounded management shell plugin for SharkSSH. */

#ifndef _SharkSshShell_h
#define _SharkSshShell_h

#include <SharkSSH.h>

#ifndef SHARKSSH_SHELL_LINE_SIZE
#define SHARKSSH_SHELL_LINE_SIZE 128
#endif

#ifndef SHARKSSH_SHELL_OUTPUT_SIZE
#define SHARKSSH_SHELL_OUTPUT_SIZE (SHARKSSH_MAX_PATH_LEN + 64)
#endif

#ifndef SHARKSSH_SHELL_INPUT_SIZE
#define SHARKSSH_SHELL_INPUT_SIZE SHARKSSH_SHELL_LINE_SIZE
#endif

typedef struct SharkSshShell SharkSshShell;

typedef enum
{
   SharkSshShellFsList,
   SharkSshShellFsChangeDirectory,
   SharkSshShellFsRead,
   SharkSshShellFsStat,
   SharkSshShellFsRemove,
   SharkSshShellFsMakeDirectory,
   SharkSshShellFsRemoveDirectory,
   SharkSshShellFsRename,
   SharkSshShellFsCopy
} SharkSshShellFsOperation;

typedef struct
{
   SharkSshChannel* channel;
   SharkSshSpan path;   /* Canonical client-visible source path. */
   SharkSshSpan target; /* Canonical client-visible target or empty. */
   int status;          /* SharkSshFsStatus or another filesystem status. */
   U8 operation;        /* SharkSshShellFsOperation */
} SharkSshShellFsEvent;

typedef struct
{
   const char* name;
   const char* help;
   int (*run)(void* context, SharkSshShell* shell, SharkSshSpan argument);
} SharkSshShellCommand;

typedef struct
{
   void* context;
   const SharkSshFileSystem* fileSystem;
   const SharkSshShellCommand* commands;
   U16 commandCount;
   const char* banner;
   int (*authorizeFile)(void* context, SharkSshChannel* channel,
                        U8 operation, SharkSshSpan path,
                        SharkSshSpan target);
   void (*auditFile)(void* context, const SharkSshShellFsEvent* event);
   U8 readOnly;
} SharkSshShellConfig;

struct SharkSshShell
{
   const SharkSshShellConfig* config;
   SharkSshChannel* channel;
   void* handle;
   void* targetHandle;
   U32 exitStatus;
   U32 copySize;
   U32 copyOffset;
   U16 outputSize;
   U16 outputOffset;
   U16 lineSize;
   U16 inputSize;
   U16 inputOffset;
   U8 output[SHARKSSH_SHELL_OUTPUT_SIZE];
   U8 line[SHARKSSH_SHELL_LINE_SIZE];
   U8 input[SHARKSSH_SHELL_INPUT_SIZE];
   char currentDirectory[SHARKSSH_MAX_PATH_LEN + 1];
   char operationPath[SHARKSSH_MAX_PATH_LEN + 1];
   char targetPath[SHARKSSH_MAX_PATH_LEN + 1];
   U8 operation;
   U8 mode;
   U8 finishPending;
   U8 closePending;
   U8 skipLf;
   U8 commandPending;
   U8 ptyActive;
   U8 echo;
   U8 echoErase;
   U8 echoNewline;
   U8 echoControl;
};

#ifdef __cplusplus
extern "C" {
#endif

void SharkSshShell_constructor(SharkSshShell* shell,
                               const SharkSshShellConfig* config);
void SharkSshShell_destructor(SharkSshShell* shell);

int SharkSshShell_pty(SharkSshShell* shell, SharkSshSpan modes);
int SharkSshShell_start(SharkSshShell* shell, SharkSshChannel* channel);
int SharkSshShell_execute(SharkSshShell* shell, SharkSshChannel* channel,
                          SharkSshSpan command);
int SharkSshShell_data(SharkSshShell* shell, SharkSshChannel* channel,
                       SharkSshSpan data);
int SharkSshShell_eof(SharkSshShell* shell, SharkSshChannel* channel);
int SharkSshShell_writable(SharkSshShell* shell, SharkSshChannel* channel);

int SharkSshShell_write(SharkSshShell* shell, const void* data, U16 size);
int SharkSshShell_writeText(SharkSshShell* shell, const char* text);
void SharkSshShell_setExitStatus(SharkSshShell* shell, U32 status);
void SharkSshShell_requestClose(SharkSshShell* shell);
int SharkSshShell_setDirectory(SharkSshShell* shell, SharkSshSpan path);
SharkSshSpan SharkSshShell_getDirectory(const SharkSshShell* shell);

#ifdef __cplusplus
}
#endif

#endif
