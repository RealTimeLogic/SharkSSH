/* Bounded management shell plugin for SharkSSH. */

#include "SharkSshShell.h"
#include <string.h>

#define SHARKSSH_SHELL_OP_NONE 0
#define SHARKSSH_SHELL_OP_LIST 1
#define SHARKSSH_SHELL_OP_CAT  2
#define SHARKSSH_SHELL_OP_COPY 3
#define SHARKSSH_SHELL_MODE_INTERACTIVE 1
#define SHARKSSH_SHELL_MODE_EXEC        2
#define SHARKSSH_TTY_OP_END              0
#define SHARKSSH_TTY_OP_ECHO            53
#define SHARKSSH_TTY_OP_ECHOE           54
#define SHARKSSH_TTY_OP_ECHONL          56
#define SHARKSSH_TTY_OP_ECHOCTL         60

static void sharkSshShellAuditFile(
   SharkSshShell* shell, U8 operation, int status,
   const char* path, const char* target);

static SharkSshSpan
sharkSshShellSpan(const char* text)
{
   SharkSshSpan span;
   span.ptr = (const U8*)text;
   span.len = (U32)strlen(text);
   return span;
}

static int
sharkSshShellSpanEqual(SharkSshSpan span, const char* text)
{
   U32 size = (U32)strlen(text);
   return span.len == size && ! memcmp(span.ptr, text, size);
}

int
SharkSshShell_write(SharkSshShell* shell, const void* data, U16 size)
{
   if( ! shell || (size && ! data))
      return SharkSshErrArgument;
   if((U32)shell->outputSize + size > sizeof(shell->output))
      return SharkSshErrBounds;
   if(size)
      memcpy(shell->output + shell->outputSize, data, size);
   shell->outputSize = (U16)(shell->outputSize + size);
   return SharkSshOk;
}

int
SharkSshShell_writeText(SharkSshShell* shell, const char* text)
{
   U32 size;
   if( ! text)
      return SharkSshErrArgument;
   size = (U32)strlen(text);
   return size > 0xFFFFU ? SharkSshErrBounds :
      SharkSshShell_write(shell, text, (U16)size);
}

void
SharkSshShell_setExitStatus(SharkSshShell* shell, U32 status)
{
   if(shell)
      shell->exitStatus = status;
}

void
SharkSshShell_requestClose(SharkSshShell* shell)
{
   if(shell)
      shell->closePending = 1;
}

static int
sharkSshShellCloseOperation(SharkSshShell* shell, int abortCopy)
{
   const SharkSshFileSystem* fs;
   int status = SharkSshFsOk;
   int closeStatus;
   if( ! shell || ! shell->handle || ! shell->config)
      return SharkSshFsOk;
   fs = shell->config->fileSystem;
   if(fs)
   {
      if(shell->operation == SHARKSSH_SHELL_OP_LIST && fs->closeDirectory)
         status = fs->closeDirectory(fs->context, shell->handle);
      else if((shell->operation == SHARKSSH_SHELL_OP_CAT ||
               shell->operation == SHARKSSH_SHELL_OP_COPY) && fs->close)
         status = fs->close(fs->context, shell->handle);
      if(shell->targetHandle && fs->close)
      {
         closeStatus = fs->close(fs->context, shell->targetHandle);
         if(status == SharkSshFsOk)
            status = closeStatus;
      }
      if(abortCopy && shell->operation == SHARKSSH_SHELL_OP_COPY &&
         shell->targetPath[0] && fs->remove)
         (void)fs->remove(fs->context, sharkSshShellSpan(shell->targetPath));
   }
   shell->handle = 0;
   shell->targetHandle = 0;
   shell->operation = SHARKSSH_SHELL_OP_NONE;
   shell->copySize = 0;
   shell->copyOffset = 0;
   return status;
}

static void
sharkSshShellAbortOperation(SharkSshShell* shell)
{
   U8 operation = shell ? shell->operation : SHARKSSH_SHELL_OP_NONE;
   int status;
   if(operation == SHARKSSH_SHELL_OP_NONE)
      return;
   status = sharkSshShellCloseOperation(shell, 1);
   if(status == SharkSshFsOk)
      status = SharkSshErrService;
   if(operation == SHARKSSH_SHELL_OP_LIST)
      sharkSshShellAuditFile(
         shell, SharkSshShellFsList, status, shell->operationPath, 0);
   else if(operation == SHARKSSH_SHELL_OP_CAT)
      sharkSshShellAuditFile(
         shell, SharkSshShellFsRead, status, shell->operationPath, 0);
   else if(operation == SHARKSSH_SHELL_OP_COPY)
      sharkSshShellAuditFile(
         shell, SharkSshShellFsCopy, status,
         shell->operationPath, shell->targetPath);
}

void
SharkSshShell_constructor(SharkSshShell* shell,
                          const SharkSshShellConfig* config)
{
   if(shell)
   {
      memset(shell, 0, sizeof(*shell));
      shell->config = config;
   }
}

void
SharkSshShell_destructor(SharkSshShell* shell)
{
   if(shell)
   {
      sharkSshShellAbortOperation(shell);
      shell->channel = 0;
   }
}

int
SharkSshShell_pty(SharkSshShell* shell, SharkSshSpan modes)
{
   U32 offset = 0;
   U8 echo = 1;
   U8 echoErase = 1;
   U8 echoNewline = 0;
   U8 echoControl = 1;
   U8 terminated = modes.len == 0;
   if( ! shell || (modes.len && ! modes.ptr))
      return SharkSshErrArgument;
   while(offset < modes.len)
   {
      U8 opcode = modes.ptr[offset++];
      U32 value;
      if(opcode == SHARKSSH_TTY_OP_END)
      {
         if(offset != modes.len)
            return SharkSshErrProtocol;
         terminated = 1;
         break;
      }
      if(modes.len - offset < 4)
         return SharkSshErrProtocol;
      value = ((U32)modes.ptr[offset] << 24) |
              ((U32)modes.ptr[offset + 1] << 16) |
              ((U32)modes.ptr[offset + 2] << 8) |
              modes.ptr[offset + 3];
      offset += 4;
      switch(opcode)
      {
         case SHARKSSH_TTY_OP_ECHO:
            echo = value != 0;
            break;
         case SHARKSSH_TTY_OP_ECHOE:
            echoErase = value != 0;
            break;
         case SHARKSSH_TTY_OP_ECHONL:
            echoNewline = value != 0;
            break;
         case SHARKSSH_TTY_OP_ECHOCTL:
            echoControl = value != 0;
            break;
         default:
            break;
      }
   }
   if( ! terminated)
      return SharkSshErrProtocol;
   shell->ptyActive = 1;
   shell->echo = echo;
   shell->echoErase = echoErase;
   shell->echoNewline = echoNewline;
   shell->echoControl = echoControl;
   return SharkSshOk;
}

static int
sharkSshShellResolvePath(const SharkSshShell* shell, SharkSshSpan input,
                         char path[SHARKSSH_MAX_PATH_LEN + 1])
{
   U32 cursor = 0;
   U16 pathSize = 0;
   if(input.len && input.ptr[0] != '/' && input.ptr[0] != '\\')
   {
      pathSize = (U16)strlen(shell->currentDirectory);
      memcpy(path, shell->currentDirectory, pathSize);
   }
   else
   {
      while(cursor < input.len &&
            (input.ptr[cursor] == '/' || input.ptr[cursor] == '\\'))
         ++cursor;
   }
   while(cursor < input.len)
   {
      U32 start;
      U16 componentSize;
      while(cursor < input.len &&
            (input.ptr[cursor] == '/' || input.ptr[cursor] == '\\'))
         ++cursor;
      if(cursor == input.len)
         break;
      start = cursor;
      while(cursor < input.len && input.ptr[cursor] != '/' &&
            input.ptr[cursor] != '\\')
         ++cursor;
      componentSize = (U16)(cursor - start);
      if(componentSize == 1 && input.ptr[start] == '.')
         continue;
      if(componentSize == 2 && input.ptr[start] == '.' &&
         input.ptr[start + 1] == '.')
      {
         while(pathSize && path[pathSize - 1] != '/')
            --pathSize;
         if(pathSize)
            --pathSize;
         continue;
      }
      if(memchr(input.ptr + start, ':', componentSize))
         return SharkSshErrArgument;
      if(pathSize)
      {
         if(pathSize >= SHARKSSH_MAX_PATH_LEN)
            return SharkSshErrBounds;
         path[pathSize++] = '/';
      }
      if((U32)pathSize + componentSize > SHARKSSH_MAX_PATH_LEN)
         return SharkSshErrBounds;
      memcpy(path + pathSize, input.ptr + start, componentSize);
      pathSize = (U16)(pathSize + componentSize);
   }
   path[pathSize] = 0;
   return SharkSshOk;
}

static SharkSshSpan
sharkSshShellVisiblePath(const char* path,
                         char visible[SHARKSSH_MAX_PATH_LEN + 2])
{
   SharkSshSpan span;
   U32 size = (U32)strlen(path);
   visible[0] = '/';
   if(size)
      memcpy(visible + 1, path, size);
   visible[size + 1] = 0;
   span.ptr = (const U8*)visible;
   span.len = size + 1;
   return span;
}

static int
sharkSshShellAuthorizeFile(SharkSshShell* shell, U8 operation,
                           const char* path, const char* target)
{
   char visiblePath[SHARKSSH_MAX_PATH_LEN + 2];
   char visibleTarget[SHARKSSH_MAX_PATH_LEN + 2];
   SharkSshSpan pathSpan = sharkSshShellVisiblePath(path, visiblePath);
   SharkSshSpan targetSpan;
   targetSpan.ptr = 0;
   targetSpan.len = 0;
   if(target)
      targetSpan = sharkSshShellVisiblePath(target, visibleTarget);
   if( ! shell->config->authorizeFile)
      return SharkSshFsOk;
   return shell->config->authorizeFile(
      shell->config->context, shell->channel, operation,
      pathSpan, targetSpan) == SharkSshOk ? SharkSshFsOk :
                                           SharkSshFsDenied;
}

static void
sharkSshShellAuditFile(SharkSshShell* shell, U8 operation, int status,
                       const char* path, const char* target)
{
   SharkSshShellFsEvent event;
   char visiblePath[SHARKSSH_MAX_PATH_LEN + 2];
   char visibleTarget[SHARKSSH_MAX_PATH_LEN + 2];
   if( ! shell->config->auditFile)
      return;
   event.channel = shell->channel;
   event.path = sharkSshShellVisiblePath(path, visiblePath);
   event.target.ptr = 0;
   event.target.len = 0;
   if(target)
      event.target = sharkSshShellVisiblePath(target, visibleTarget);
   event.status = status;
   event.operation = operation;
   shell->config->auditFile(shell->config->context, &event);
}

static int
sharkSshShellMutatingAllowed(const SharkSshShell* shell)
{
   return ! shell->config->readOnly;
}

int
SharkSshShell_setDirectory(SharkSshShell* shell, SharkSshSpan path)
{
   const SharkSshFileSystem* fs;
   SharkSshFsStat stat;
   char resolved[SHARKSSH_MAX_PATH_LEN + 1];
   int status;
   if( ! shell || ! shell->config || ! shell->config->fileSystem)
      return SharkSshErrService;
   fs = shell->config->fileSystem;
   if( ! fs->stat)
      return SharkSshErrService;
   status = sharkSshShellResolvePath(shell, path, resolved);
   if(status)
      return status;
   status = sharkSshShellAuthorizeFile(
      shell, SharkSshShellFsChangeDirectory, resolved, 0);
   if(status == SharkSshFsOk)
      status = fs->stat(fs->context, sharkSshShellSpan(resolved), &stat);
   if(status == SharkSshFsOk && stat.type != SharkSshFsTypeDirectory)
      status = SharkSshFsNotFound;
   sharkSshShellAuditFile(
      shell, SharkSshShellFsChangeDirectory, status, resolved, 0);
   if(status != SharkSshFsOk)
      return SharkSshErrService;
   strcpy(shell->currentDirectory, resolved);
   return SharkSshOk;
}

SharkSshSpan
SharkSshShell_getDirectory(const SharkSshShell* shell)
{
   SharkSshSpan span;
   span.ptr = shell ? (const U8*)shell->currentDirectory : 0;
   span.len = shell ? (U32)strlen(shell->currentDirectory) : 0;
   return span;
}

static int
sharkSshShellQueuePath(SharkSshShell* shell)
{
   int status = SharkSshShell_writeText(shell, "/");
   if( ! status && shell->currentDirectory[0])
      status = SharkSshShell_writeText(shell, shell->currentDirectory);
   return status;
}

static int
sharkSshShellQueuePrompt(SharkSshShell* shell)
{
   int status = SharkSshShell_writeText(shell, "sharkssh:");
   if( ! status)
      status = sharkSshShellQueuePath(shell);
   if( ! status)
      status = SharkSshShell_writeText(shell, "> ");
   return status;
}

static void
sharkSshShellSplit(SharkSshSpan line, SharkSshSpan* command,
                   SharkSshSpan* argument)
{
   U32 start = 0;
   U32 end = line.len;
   U32 split;
   while(start < end && (line.ptr[start] == ' ' || line.ptr[start] == '\t'))
      ++start;
   while(end > start && (line.ptr[end - 1] == ' ' ||
                         line.ptr[end - 1] == '\t'))
      --end;
   split = start;
   while(split < end && line.ptr[split] != ' ' && line.ptr[split] != '\t')
      ++split;
   command->ptr = line.ptr + start;
   command->len = split - start;
   while(split < end && (line.ptr[split] == ' ' || line.ptr[split] == '\t'))
      ++split;
   argument->ptr = line.ptr + split;
   argument->len = end - split;
}

static int
sharkSshShellQueueHelp(SharkSshShell* shell)
{
   U16 i;
   int status = SharkSshShell_writeText(
      shell, "help  pwd  ls [path]  cd [path]  cat <file>  stat <path>  "
             "rm <file>  mkdir <dir>  rmdir <dir>  mv <from> <to>  "
             "cp <from> <to>  exit");
   if( ! shell->config)
      return status;
   for(i = 0; ! status && i < shell->config->commandCount; ++i)
   {
      status = SharkSshShell_writeText(shell, "  ");
      if( ! status)
         status = SharkSshShell_writeText(
            shell, shell->config->commands[i].help ?
                   shell->config->commands[i].help :
                   shell->config->commands[i].name);
   }
   if( ! status)
      status = SharkSshShell_writeText(shell, "\r\n");
   return status;
}

static int
sharkSshShellFileSystemNotConfigured(SharkSshShell* shell,
                                     SharkSshSpan command)
{
   int status;
   shell->exitStatus = 1;
   status = SharkSshShell_write(shell, command.ptr, (U16)command.len);
   if( ! status)
      status = SharkSshShell_writeText(
         shell, ": filesystem not configured\r\n");
   return status;
}

static int
sharkSshShellIsFileSystemCommand(SharkSshSpan command)
{
   return sharkSshShellSpanEqual(command, "ls") ||
          sharkSshShellSpanEqual(command, "cd") ||
          sharkSshShellSpanEqual(command, "cat") ||
          sharkSshShellSpanEqual(command, "stat") ||
          sharkSshShellSpanEqual(command, "rm") ||
          sharkSshShellSpanEqual(command, "mkdir") ||
          sharkSshShellSpanEqual(command, "rmdir") ||
          sharkSshShellSpanEqual(command, "mv") ||
          sharkSshShellSpanEqual(command, "cp");
}

static int
sharkSshShellStartList(SharkSshShell* shell, SharkSshSpan argument)
{
   const SharkSshFileSystem* fs = shell->config->fileSystem;
   char path[SHARKSSH_MAX_PATH_LEN + 1];
   int status;
   if( ! fs || ! fs->openDirectory || ! fs->readDirectory ||
      ! fs->closeDirectory)
   {
      shell->exitStatus = 1;
      return SharkSshShell_writeText(shell, "ls: unavailable\r\n");
   }
   if(argument.len)
      status = sharkSshShellResolvePath(shell, argument, path);
   else
   {
      strcpy(path, shell->currentDirectory);
      status = SharkSshOk;
   }
   if(status)
   {
      shell->exitStatus = 1;
      return SharkSshShell_writeText(shell, "ls: invalid path\r\n");
   }
   status = sharkSshShellAuthorizeFile(
      shell, SharkSshShellFsList, path, 0);
   if(status == SharkSshFsOk)
      status = fs->openDirectory(fs->context, sharkSshShellSpan(path),
                                 &shell->handle);
   if(status == SharkSshFsOk && ! shell->handle)
      status = SharkSshErrService;
   if(status != SharkSshFsOk)
   {
      shell->exitStatus = 1;
      sharkSshShellAuditFile(
         shell, SharkSshShellFsList, status, path, 0);
      return SharkSshShell_writeText(shell, "ls: directory not found\r\n");
   }
   strcpy(shell->operationPath, path);
   shell->operation = SHARKSSH_SHELL_OP_LIST;
   return SharkSshOk;
}

static int
sharkSshShellStartCat(SharkSshShell* shell, SharkSshSpan argument)
{
   const SharkSshFileSystem* fs = shell->config->fileSystem;
   char path[SHARKSSH_MAX_PATH_LEN + 1];
   int status;
   if( ! argument.len)
   {
      shell->exitStatus = 1;
      return SharkSshShell_writeText(shell, "cat: file name required\r\n");
   }
   if( ! fs || ! fs->open || ! fs->read || ! fs->close)
   {
      shell->exitStatus = 1;
      return SharkSshShell_writeText(shell, "cat: unavailable\r\n");
   }
   status = sharkSshShellResolvePath(shell, argument, path);
   if(status)
   {
      shell->exitStatus = 1;
      return SharkSshShell_writeText(shell, "cat: invalid path\r\n");
   }
   status = sharkSshShellAuthorizeFile(
      shell, SharkSshShellFsRead, path, 0);
   if(status == SharkSshFsOk)
      status = fs->open(fs->context, sharkSshShellSpan(path),
                        SharkSshFsOpenRead, &shell->handle);
   if(status == SharkSshFsOk && ! shell->handle)
      status = SharkSshErrService;
   if(status != SharkSshFsOk)
   {
      shell->exitStatus = 1;
      sharkSshShellAuditFile(
         shell, SharkSshShellFsRead, status, path, 0);
      return SharkSshShell_writeText(shell, "cat: file not found\r\n");
   }
   strcpy(shell->operationPath, path);
   shell->operation = SHARKSSH_SHELL_OP_CAT;
   return SharkSshOk;
}

static int
sharkSshShellCommandError(SharkSshShell* shell, const char* command,
                          const char* message)
{
   int status;
   shell->exitStatus = 1;
   status = SharkSshShell_writeText(shell, command);
   if( ! status)
      status = SharkSshShell_writeText(shell, ": ");
   if( ! status)
      status = SharkSshShell_writeText(shell, message);
   if( ! status)
      status = SharkSshShell_writeText(shell, "\r\n");
   return status;
}

static int
sharkSshShellSplitPair(SharkSshSpan input, SharkSshSpan* first,
                       SharkSshSpan* second)
{
   U32 cursor = 0;
   U32 start;
   while(cursor < input.len &&
         (input.ptr[cursor] == ' ' || input.ptr[cursor] == '\t'))
      ++cursor;
   start = cursor;
   while(cursor < input.len && input.ptr[cursor] != ' ' &&
         input.ptr[cursor] != '\t')
      ++cursor;
   first->ptr = input.ptr + start;
   first->len = cursor - start;
   while(cursor < input.len &&
         (input.ptr[cursor] == ' ' || input.ptr[cursor] == '\t'))
      ++cursor;
   start = cursor;
   while(cursor < input.len && input.ptr[cursor] != ' ' &&
         input.ptr[cursor] != '\t')
      ++cursor;
   second->ptr = input.ptr + start;
   second->len = cursor - start;
   while(cursor < input.len &&
         (input.ptr[cursor] == ' ' || input.ptr[cursor] == '\t'))
      ++cursor;
   return first->len && second->len && cursor == input.len ?
      SharkSshOk : SharkSshErrArgument;
}

static int
sharkSshShellPathCommand(SharkSshShell* shell, SharkSshSpan argument,
                         U8 operation, const char* command)
{
   const SharkSshFileSystem* fs = shell->config->fileSystem;
   char path[SHARKSSH_MAX_PATH_LEN + 1];
   int status;
   if( ! argument.len)
      return sharkSshShellCommandError(shell, command, "path required");
   status = sharkSshShellResolvePath(shell, argument, path);
   if(status)
      return sharkSshShellCommandError(shell, command, "invalid path");
   if( ! sharkSshShellMutatingAllowed(shell))
      status = SharkSshFsDenied;
   else
      status = sharkSshShellAuthorizeFile(shell, operation, path, 0);
   if(status == SharkSshFsOk)
   {
      switch(operation)
      {
         case SharkSshShellFsRemove:
            status = fs && fs->remove ? fs->remove(
               fs->context, sharkSshShellSpan(path)) :
               SharkSshFsUnsupported;
            break;
         case SharkSshShellFsMakeDirectory:
            status = fs && fs->makeDirectory ? fs->makeDirectory(
               fs->context, sharkSshShellSpan(path), 0755) :
               SharkSshFsUnsupported;
            break;
         default:
            status = fs && fs->removeDirectory ? fs->removeDirectory(
               fs->context, sharkSshShellSpan(path)) :
               SharkSshFsUnsupported;
            break;
      }
   }
   sharkSshShellAuditFile(shell, operation, status, path, 0);
   return status == SharkSshFsOk ? SharkSshOk :
      sharkSshShellCommandError(
         shell, command, status == SharkSshFsDenied ? "permission denied" :
                                                     "failed");
}

static int
sharkSshShellMove(SharkSshShell* shell, SharkSshSpan argument)
{
   const SharkSshFileSystem* fs = shell->config->fileSystem;
   SharkSshSpan source;
   SharkSshSpan target;
   char sourcePath[SHARKSSH_MAX_PATH_LEN + 1];
   char targetPath[SHARKSSH_MAX_PATH_LEN + 1];
   int status = sharkSshShellSplitPair(argument, &source, &target);
   if(status)
      return sharkSshShellCommandError(shell, "mv", "two paths required");
   status = sharkSshShellResolvePath(shell, source, sourcePath);
   if( ! status)
      status = sharkSshShellResolvePath(shell, target, targetPath);
   if(status)
      return sharkSshShellCommandError(shell, "mv", "invalid path");
   if( ! sharkSshShellMutatingAllowed(shell))
      status = SharkSshFsDenied;
   else
      status = sharkSshShellAuthorizeFile(
         shell, SharkSshShellFsRename, sourcePath, targetPath);
   if(status == SharkSshFsOk)
      status = fs && fs->rename ? fs->rename(
         fs->context, sharkSshShellSpan(sourcePath),
         sharkSshShellSpan(targetPath)) : SharkSshFsUnsupported;
   sharkSshShellAuditFile(
      shell, SharkSshShellFsRename, status, sourcePath, targetPath);
   return status == SharkSshFsOk ? SharkSshOk :
      sharkSshShellCommandError(
         shell, "mv", status == SharkSshFsDenied ? "permission denied" :
                                                   "failed");
}

static int
sharkSshShellWriteUnsigned(SharkSshShell* shell, U64 value)
{
   char text[21];
   U16 offset = sizeof(text);
   do
   {
      text[--offset] = (char)('0' + (value % 10));
      value /= 10;
   }
   while(value);
   return SharkSshShell_write(shell, text + offset,
                              (U16)(sizeof(text) - offset));
}

static int
sharkSshShellStat(SharkSshShell* shell, SharkSshSpan argument)
{
   const SharkSshFileSystem* fs = shell->config->fileSystem;
   SharkSshFsStat fileStat;
   char path[SHARKSSH_MAX_PATH_LEN + 1];
   char permissions[4];
   U16 i;
   int status;
   if( ! argument.len)
      return sharkSshShellCommandError(shell, "stat", "path required");
   status = sharkSshShellResolvePath(shell, argument, path);
   if(status)
      return sharkSshShellCommandError(shell, "stat", "invalid path");
   status = sharkSshShellAuthorizeFile(
      shell, SharkSshShellFsStat, path, 0);
   if(status == SharkSshFsOk)
      status = fs && fs->stat ? fs->stat(
         fs->context, sharkSshShellSpan(path), &fileStat) :
         SharkSshFsUnsupported;
   sharkSshShellAuditFile(shell, SharkSshShellFsStat, status, path, 0);
   if(status != SharkSshFsOk)
      return sharkSshShellCommandError(
         shell, "stat", status == SharkSshFsDenied ? "permission denied" :
                                                     "failed");
   status = SharkSshShell_writeText(
      shell, fileStat.type == SharkSshFsTypeDirectory ? "directory" :
             fileStat.type == SharkSshFsTypeFile ? "file" : "other");
   if( ! status)
      status = SharkSshShell_writeText(shell, " size=");
   if( ! status)
      status = sharkSshShellWriteUnsigned(
         shell, ((U64)fileStat.sizeHi << 32) | fileStat.sizeLo);
   if( ! status)
      status = SharkSshShell_writeText(shell, " modified=");
   if( ! status)
      status = sharkSshShellWriteUnsigned(shell, fileStat.modifiedTime);
   for(i = 0; i < 4; ++i)
      permissions[i] = (char)('0' +
         ((fileStat.permissions >> ((3 - i) * 3)) & 7));
   if( ! status)
      status = SharkSshShell_writeText(shell, " permissions=");
   if( ! status)
      status = SharkSshShell_write(shell, permissions, sizeof(permissions));
   if( ! status)
      status = SharkSshShell_writeText(shell, "\r\n");
   return status;
}

static int
sharkSshShellStartCopy(SharkSshShell* shell, SharkSshSpan argument)
{
   const SharkSshFileSystem* fs = shell->config->fileSystem;
   SharkSshSpan source;
   SharkSshSpan target;
   SharkSshFsStat fileStat;
   char sourcePath[SHARKSSH_MAX_PATH_LEN + 1];
   char targetPath[SHARKSSH_MAX_PATH_LEN + 1];
   int status = sharkSshShellSplitPair(argument, &source, &target);
   if(status)
      return sharkSshShellCommandError(shell, "cp", "two paths required");
   status = sharkSshShellResolvePath(shell, source, sourcePath);
   if( ! status)
      status = sharkSshShellResolvePath(shell, target, targetPath);
   if(status || ! strcmp(sourcePath, targetPath))
      return sharkSshShellCommandError(shell, "cp", "invalid path");
   if( ! fs || ! fs->open || ! fs->close || ! fs->read || ! fs->write ||
      ! fs->remove)
      return sharkSshShellCommandError(shell, "cp", "unavailable");
   if( ! sharkSshShellMutatingAllowed(shell))
      status = SharkSshFsDenied;
   else
      status = sharkSshShellAuthorizeFile(
         shell, SharkSshShellFsCopy, sourcePath, targetPath);
   if(status == SharkSshFsOk)
      status = fs->open(fs->context, sharkSshShellSpan(sourcePath),
                        SharkSshFsOpenRead, &shell->handle);
   if(status == SharkSshFsOk && ! shell->handle)
      status = SharkSshErrService;
   if(status == SharkSshFsOk)
   {
      status = fs->open(
         fs->context, sharkSshShellSpan(targetPath),
         SharkSshFsOpenWrite | SharkSshFsOpenCreate |
         SharkSshFsOpenTruncate | SharkSshFsOpenExclusive,
         &shell->targetHandle);
      if(status == SharkSshFsUnsupported && fs->stat)
      {
         status = fs->stat(
            fs->context, sharkSshShellSpan(targetPath), &fileStat);
         if(status == SharkSshFsNotFound)
            status = fs->open(
               fs->context, sharkSshShellSpan(targetPath),
               SharkSshFsOpenWrite | SharkSshFsOpenCreate |
               SharkSshFsOpenTruncate, &shell->targetHandle);
         else if(status == SharkSshFsOk)
            status = SharkSshFsExists;
      }
      if(status == SharkSshFsOk && ! shell->targetHandle)
         status = SharkSshErrService;
   }
   if(status != SharkSshFsOk)
   {
      if(shell->targetHandle)
      {
         (void)fs->close(fs->context, shell->targetHandle);
         shell->targetHandle = 0;
         (void)fs->remove(fs->context, sharkSshShellSpan(targetPath));
      }
      if(shell->handle)
      {
         (void)fs->close(fs->context, shell->handle);
         shell->handle = 0;
      }
      sharkSshShellAuditFile(
         shell, SharkSshShellFsCopy, status, sourcePath, targetPath);
      return sharkSshShellCommandError(
         shell, "cp", status == SharkSshFsDenied ? "permission denied" :
                      status == SharkSshFsExists ? "target exists" :
                                                   "failed");
   }
   strcpy(shell->operationPath, sourcePath);
   strcpy(shell->targetPath, targetPath);
   shell->copySize = 0;
   shell->copyOffset = 0;
   shell->operation = SHARKSSH_SHELL_OP_COPY;
   return SharkSshOk;
}

static int
sharkSshShellRunCommand(SharkSshShell* shell, SharkSshSpan line)
{
   SharkSshSpan command;
   SharkSshSpan argument;
   U16 i;
   int status = SharkSshOk;
   sharkSshShellSplit(line, &command, &argument);
   shell->exitStatus = 0;
   shell->closePending = 0;
   if( ! command.len)
      ;
   else if(sharkSshShellSpanEqual(command, "help"))
      status = sharkSshShellQueueHelp(shell);
   else if(sharkSshShellSpanEqual(command, "pwd"))
   {
      status = sharkSshShellQueuePath(shell);
      if( ! status)
         status = SharkSshShell_writeText(shell, "\r\n");
   }
   else if((! shell->config || ! shell->config->fileSystem) &&
           sharkSshShellIsFileSystemCommand(command))
      status = sharkSshShellFileSystemNotConfigured(shell, command);
   else if(sharkSshShellSpanEqual(command, "ls"))
      status = sharkSshShellStartList(shell, argument);
   else if(sharkSshShellSpanEqual(command, "cd"))
   {
      status = SharkSshShell_setDirectory(shell, argument);
      if(status)
      {
         shell->exitStatus = 1;
         status = SharkSshShell_writeText(
            shell, "cd: directory not found\r\n");
      }
   }
   else if(sharkSshShellSpanEqual(command, "cat"))
      status = sharkSshShellStartCat(shell, argument);
   else if(sharkSshShellSpanEqual(command, "stat"))
      status = sharkSshShellStat(shell, argument);
   else if(sharkSshShellSpanEqual(command, "rm"))
      status = sharkSshShellPathCommand(
         shell, argument, SharkSshShellFsRemove, "rm");
   else if(sharkSshShellSpanEqual(command, "mkdir"))
      status = sharkSshShellPathCommand(
         shell, argument, SharkSshShellFsMakeDirectory, "mkdir");
   else if(sharkSshShellSpanEqual(command, "rmdir"))
      status = sharkSshShellPathCommand(
         shell, argument, SharkSshShellFsRemoveDirectory, "rmdir");
   else if(sharkSshShellSpanEqual(command, "mv"))
      status = sharkSshShellMove(shell, argument);
   else if(sharkSshShellSpanEqual(command, "cp"))
      status = sharkSshShellStartCopy(shell, argument);
   else if(sharkSshShellSpanEqual(command, "exit") ||
           sharkSshShellSpanEqual(command, "quit"))
   {
      if(shell->mode == SHARKSSH_SHELL_MODE_INTERACTIVE)
         status = SharkSshShell_writeText(shell, "Bye\r\n");
      shell->closePending = 1;
   }
   else
   {
      for(i = 0; shell->config && i < shell->config->commandCount; ++i)
      {
         const SharkSshShellCommand* custom = &shell->config->commands[i];
         if(custom->name && sharkSshShellSpanEqual(command, custom->name))
         {
            status = custom->run ? custom->run(
               shell->config->context, shell, argument) :
               SharkSshErrService;
            break;
         }
      }
      if( ! shell->config || i == shell->config->commandCount)
      {
         shell->exitStatus = 127;
         status = SharkSshShell_writeText(shell, "Unknown command\r\n");
      }
      else if(status)
      {
         shell->exitStatus = 1;
         status = SharkSshShell_writeText(shell, "Command failed\r\n");
      }
   }
   if( ! shell->operation)
      shell->finishPending = 1;
   return status;
}

static int
sharkSshShellReset(SharkSshShell* shell, SharkSshChannel* channel, U8 mode)
{
   const SharkSshShellConfig* config;
   U8 ptyActive;
   U8 echo;
   U8 echoErase;
   U8 echoNewline;
   U8 echoControl;
   if( ! shell || ! channel || ! shell->config ||
      (shell->config->commandCount && ! shell->config->commands))
      return SharkSshErrArgument;
   config = shell->config;
   ptyActive = shell->ptyActive;
   echo = shell->echo;
   echoErase = shell->echoErase;
   echoNewline = shell->echoNewline;
   echoControl = shell->echoControl;
   sharkSshShellAbortOperation(shell);
   memset(shell, 0, sizeof(*shell));
   shell->config = config;
   shell->channel = channel;
   shell->mode = mode;
   shell->ptyActive = ptyActive;
   shell->echo = echo;
   shell->echoErase = echoErase;
   shell->echoNewline = echoNewline;
   shell->echoControl = echoControl;
   return SharkSshOk;
}

int
SharkSshShell_start(SharkSshShell* shell, SharkSshChannel* channel)
{
   int status = sharkSshShellReset(
      shell, channel, SHARKSSH_SHELL_MODE_INTERACTIVE);
   if( ! status && shell->config->banner)
      status = SharkSshShell_writeText(shell, shell->config->banner);
   if( ! status)
      shell->finishPending = 1;
   return status;
}

int
SharkSshShell_execute(SharkSshShell* shell, SharkSshChannel* channel,
                      SharkSshSpan command)
{
   int status = sharkSshShellReset(shell, channel, SHARKSSH_SHELL_MODE_EXEC);
   if(status)
      return status;
   if(command.len > sizeof(shell->line))
      return SharkSshErrBounds;
   if(command.len)
      memcpy(shell->line, command.ptr, command.len);
   shell->lineSize = (U16)command.len;
   return sharkSshShellRunCommand(shell, command);
}

int
SharkSshShell_data(SharkSshShell* shell, SharkSshChannel* channel,
                   SharkSshSpan data)
{
   if( ! shell || shell->channel != channel ||
      shell->mode != SHARKSSH_SHELL_MODE_INTERACTIVE)
      return SharkSshErrState;
   while(data.len)
   {
      U32 available;
      U32 size;
      int status;
      if(shell->inputOffset)
      {
         if(shell->inputOffset < shell->inputSize)
         {
            memmove(shell->input,
                    shell->input + shell->inputOffset,
                    shell->inputSize - shell->inputOffset);
            shell->inputSize = (U16)(shell->inputSize - shell->inputOffset);
         }
         else
            shell->inputSize = 0;
         shell->inputOffset = 0;
      }
      available = sizeof(shell->input) - shell->inputSize;
      if( ! available)
         return SharkSshErrBounds;
      size = data.len < available ? data.len : available;
      memcpy(shell->input + shell->inputSize, data.ptr, size);
      shell->inputSize = (U16)(shell->inputSize + size);
      data.ptr += size;
      data.len -= size;
      status = SharkSshShell_writable(shell, channel);
      if(status && status != SharkSshTimeout)
         return status;
   }
   return SharkSshOk;
}

static int
sharkSshShellProcessInput(SharkSshShell* shell)
{
   int status = SharkSshOk;
   while(shell->inputOffset < shell->inputSize)
   {
      U8 ch = shell->input[shell->inputOffset];
      U16 echoSize = 0;
      if(ch == 3)
         echoSize = ! shell->ptyActive ||
                    (shell->echo && shell->echoControl) ? 4 : 0;
      else if(ch == '\r' || ch == '\n')
         echoSize = ! shell->ptyActive || shell->echo ||
                    shell->echoNewline ? 2 : 0;
      else if((ch == 8 || ch == 127) && shell->lineSize &&
              shell->ptyActive && shell->echo)
         echoSize = shell->echoErase ? 3 : 1;
      else if(ch >= 32 && ch < 127 && shell->ptyActive && shell->echo)
         echoSize = 1;
      if((U32)shell->outputSize + echoSize > sizeof(shell->output))
         break;
      ++shell->inputOffset;
      if(ch == 3)
      {
         if(echoSize)
            status = SharkSshShell_writeText(shell, "^C\r\n");
         if( ! status)
         {
            shell->exitStatus = 130;
            shell->closePending = 1;
            shell->finishPending = 1;
         }
      }
      else if(ch == '\r' || ch == '\n')
      {
         if(ch == '\n' && shell->skipLf)
         {
            shell->skipLf = 0;
            continue;
         }
         shell->skipLf = ch == '\r';
         if(echoSize)
            status = SharkSshShell_writeText(shell, "\r\n");
         if( ! status)
            shell->commandPending = 1;
      }
      else if(ch == 8 || ch == 127)
      {
         shell->skipLf = 0;
         if(shell->lineSize)
         {
            --shell->lineSize;
            if(echoSize)
               status = SharkSshShell_writeText(
                  shell, shell->echoErase ? "\b \b" : "\b");
         }
      }
      else if(ch >= 32 && ch < 127)
      {
         shell->skipLf = 0;
         if(shell->lineSize == sizeof(shell->line))
            return SharkSshErrBounds;
         shell->line[shell->lineSize++] = ch;
         if(echoSize)
            status = SharkSshShell_write(shell, &ch, 1);
      }
      if(status)
         return status;
      if(shell->operation || shell->finishPending || shell->commandPending)
         break;
   }
   if(shell->inputOffset == shell->inputSize)
   {
      shell->inputOffset = 0;
      shell->inputSize = 0;
   }
   return SharkSshOk;
}

int
SharkSshShell_eof(SharkSshShell* shell, SharkSshChannel* channel)
{
   if( ! shell || shell->channel != channel)
      return SharkSshErrState;
   if(shell->mode == SHARKSSH_SHELL_MODE_INTERACTIVE)
   {
      shell->closePending = 1;
      shell->finishPending = 1;
      return SharkSshShell_writable(shell, channel);
   }
   return SharkSshOk;
}

static int
sharkSshShellFillList(SharkSshShell* shell)
{
   const SharkSshFileSystem* fs = shell->config->fileSystem;
   SharkSshFsStat stat;
   U8 name[SHARKSSH_MAX_PATH_LEN];
   U16 size;
   int status = fs->readDirectory(fs->context, shell->handle, name,
                                  sizeof(name), &size, &stat);
   if(status == SharkSshFsEnd)
   {
      status = sharkSshShellCloseOperation(shell, 0);
      sharkSshShellAuditFile(
         shell, SharkSshShellFsList, status, shell->operationPath, 0);
      shell->finishPending = 1;
      return status == SharkSshFsOk ? SharkSshOk :
         sharkSshShellCommandError(shell, "ls", "close failed");
   }
   if(status != SharkSshFsOk)
   {
      (void)sharkSshShellCloseOperation(shell, 0);
      sharkSshShellAuditFile(
         shell, SharkSshShellFsList, status, shell->operationPath, 0);
      shell->exitStatus = 1;
      shell->finishPending = 1;
      return SharkSshShell_writeText(shell, "ls: read failed\r\n");
   }
   status = SharkSshShell_writeText(
      shell, stat.type == SharkSshFsTypeDirectory ? "d " :
             stat.type == SharkSshFsTypeFile ? "- " : "? ");
   if( ! status)
      status = SharkSshShell_write(shell, name, size);
   if( ! status)
      status = SharkSshShell_writeText(shell, "\r\n");
   return status;
}

static int
sharkSshShellFillCat(SharkSshShell* shell)
{
   const SharkSshFileSystem* fs = shell->config->fileSystem;
   U32 size = 0;
   int status = fs->read(fs->context, shell->handle, shell->output,
                         sizeof(shell->output), &size);
   if(status != SharkSshFsOk || ! size)
   {
      int closeStatus = sharkSshShellCloseOperation(shell, 0);
      if(status == SharkSshFsOk)
         status = closeStatus;
      sharkSshShellAuditFile(
         shell, SharkSshShellFsRead, status, shell->operationPath, 0);
      shell->finishPending = 1;
      if(status != SharkSshFsOk)
      {
         shell->exitStatus = 1;
         return SharkSshShell_writeText(shell, "\r\ncat: read failed\r\n");
      }
      return SharkSshShell_writeText(shell, "\r\n");
   }
   shell->outputSize = (U16)size;
   shell->outputOffset = 0;
   return SharkSshOk;
}

static void
sharkSshShellCooperate(SharkSshShell* shell)
{
   const SharkSshPlatform* platform;
   if( ! shell->channel || ! shell->channel->connection ||
      ! shell->channel->connection->config)
      return;
   platform = &shell->channel->connection->config->platform;
   if(platform->cooperate)
      platform->cooperate(platform->context);
}

static int
sharkSshShellFinishCopy(SharkSshShell* shell, int status)
{
   const SharkSshFileSystem* fs = shell->config->fileSystem;
   int closeStatus = sharkSshShellCloseOperation(
      shell, status != SharkSshFsOk);
   if(status == SharkSshFsOk && closeStatus != SharkSshFsOk)
   {
      status = closeStatus;
      if(fs->remove)
         (void)fs->remove(
            fs->context, sharkSshShellSpan(shell->targetPath));
   }
   sharkSshShellAuditFile(
      shell, SharkSshShellFsCopy, status,
      shell->operationPath, shell->targetPath);
   shell->finishPending = 1;
   return status == SharkSshFsOk ? SharkSshOk :
      sharkSshShellCommandError(shell, "cp", "failed");
}

static int
sharkSshShellFillCopy(SharkSshShell* shell)
{
   const SharkSshFileSystem* fs = shell->config->fileSystem;
   for(;;)
   {
      int status;
      if(shell->copyOffset < shell->copySize)
      {
         U32 written = 0;
         status = fs->write(
            fs->context, shell->targetHandle,
            shell->output + shell->copyOffset,
            shell->copySize - shell->copyOffset, &written);
         if(status != SharkSshFsOk || ! written ||
            written > shell->copySize - shell->copyOffset)
            return sharkSshShellFinishCopy(
               shell, status == SharkSshFsOk ? SharkSshFsNoSpace : status);
         shell->copyOffset += written;
         if(shell->copyOffset < shell->copySize)
            continue;
         shell->copyOffset = 0;
         shell->copySize = 0;
         sharkSshShellCooperate(shell);
      }
      status = fs->read(
         fs->context, shell->handle, shell->output,
         sizeof(shell->output), &shell->copySize);
      if(status != SharkSshFsOk)
         return sharkSshShellFinishCopy(shell, status);
      if( ! shell->copySize)
         return sharkSshShellFinishCopy(shell, SharkSshFsOk);
      shell->copyOffset = 0;
   }
}

int
SharkSshShell_writable(SharkSshShell* shell, SharkSshChannel* channel)
{
   int status;
   if( ! shell || shell->channel != channel)
      return SharkSshErrState;
   for(;;)
   {
      if(shell->outputOffset < shell->outputSize)
      {
         U32 written = 0;
         status = SharkSshChannel_writeSome(
            channel, shell->output + shell->outputOffset,
            shell->outputSize - shell->outputOffset, &written);
         shell->outputOffset = (U16)(shell->outputOffset + written);
         if(status)
            return status;
      }
      shell->outputOffset = 0;
      shell->outputSize = 0;
      if(shell->commandPending)
      {
         SharkSshSpan line;
         shell->commandPending = 0;
         line.ptr = shell->line;
         line.len = shell->lineSize;
         status = sharkSshShellRunCommand(shell, line);
         shell->lineSize = 0;
         if(status)
            return status;
         continue;
      }
      if(shell->operation == SHARKSSH_SHELL_OP_LIST)
      {
         status = sharkSshShellFillList(shell);
         if(status)
            return status;
         continue;
      }
      if(shell->operation == SHARKSSH_SHELL_OP_CAT)
      {
         status = sharkSshShellFillCat(shell);
         if(status)
            return status;
         continue;
      }
      if(shell->operation == SHARKSSH_SHELL_OP_COPY)
      {
         status = sharkSshShellFillCopy(shell);
         if(status)
            return status;
         continue;
      }
      if(shell->finishPending)
      {
         shell->finishPending = 0;
         if(shell->mode == SHARKSSH_SHELL_MODE_EXEC || shell->closePending)
         {
            status = SharkSshChannel_sendExitStatus(
               channel, shell->exitStatus);
            if( ! status)
               status = SharkSshChannel_close(channel);
            return status;
         }
         status = sharkSshShellQueuePrompt(shell);
         if(status)
            return status;
         continue;
      }
      if(shell->mode == SHARKSSH_SHELL_MODE_INTERACTIVE &&
         shell->inputOffset < shell->inputSize)
      {
         status = sharkSshShellProcessInput(shell);
         if(status)
            return status;
         continue;
      }
      return SharkSshOk;
   }
}
