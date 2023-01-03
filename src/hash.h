
/* hash.c */

#define SHA1_OUTPUT_LEN 20
#define SHA1_HEXBUF_LEN (2 * SHA1_OUTPUT_LEN + 1)

char *get_file_hash(char *fname);
