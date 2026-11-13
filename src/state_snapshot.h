#ifndef STATE_SNAPSHOT_H
#define STATE_SNAPSHOT_H
void state_snapshot_start(const char *path, unsigned period);
int state_snapshot_stop(void);
#endif
