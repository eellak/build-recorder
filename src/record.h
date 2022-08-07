#include <sys/types.h> // pid_t
#include <stdint.h> // uint8_t

void record_start(char *fname);
void record_process_start(pid_t pid, char *cmd_line);
void record_process_end(pid_t pid);
void record_fileuse(pid_t pid, char *path, int purpose, uint8_t *hash);
