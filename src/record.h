#include <sys/types.h>		       // pid_t

/* record.c */
void record_start(char *fname);
void record_process_start(pid_t pid);
void record_process_end(pid_t pid);
void record_process_env(pid_t pid, char **envp);
void record_fileuse(pid_t pid, char *path, int purpose, char *hash);
