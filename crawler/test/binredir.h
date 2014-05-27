#ifndef __BINREDIR_H
#define __BINREDIR_H





typedef struct SBinRedir TBinRedir;

void       binredir_exec(char* cmdline);

TBinRedir* binredir_launch(char* cmdline);
int        binredir_stop(TBinRedir** handle);
int        binredir_get(TBinRedir* handle, char* buff, int size, int timeout_sec);







#endif

