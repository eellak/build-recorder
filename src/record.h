#include "types.h"

/* record.c */
void record_start(char *fname);
void record_process_start(pid_t pid, char *cmd_line);
void record_process_end(pid_t pid);
void record_fileuse(pid_t pid, const FILE_INFO *file);
