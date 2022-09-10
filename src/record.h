#include <sys/types.h>		       // pid_t

/* record.c */
void record_start(char *fname);
void record_process_start(pid_t pid, char *poutname);
void record_process_end(char *poutname);
void record_process_env(char *poutname, char **envp);
void record_fileuse(char *poutname, char *foutname, char *path, int purpose,
		    char *hash);
void record_rename(char *poutname, char *from, char *to);
