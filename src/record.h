#include <sys/types.h>		       // pid_t

/* record.c */
void record_start(char *fname);
void record_process_start(pid_t pid, char *poutname);
void record_process_end(char *poutname);
void record_process_env(char *poutname, char **envp);
void record_rename(char *poutname, char *from_foutname, char *to_foutname);
void record_file(char *foutname, char *path, char *abspath);
void record_fileuse(char *poutname, char *foutname, int purpose);
void record_hash(char *foutname, char *hash);
void record_size(char *foutname, size_t sz);
void record_process_create(char *p1outname, char *p2outname);
void record_exec(char *poutname, char *foutname);
