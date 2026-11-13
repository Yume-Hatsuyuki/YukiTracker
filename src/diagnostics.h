#ifndef DIAGNOSTICS_H
#define DIAGNOSTICS_H
#include "trackerlogic.h"
extern unsigned diag_slots, busy_slots, busy_gap, busy_decay, busy_bits;
void diag_start(void);
void diag_stop(void);
void diag_record(const ot_ip6 ip, const char *request, size_t len);
void diag_renew(const ot_ip6 ip, unsigned age);
size_t diag_render(char *out, size_t cap, int busy, unsigned limit);
#endif
