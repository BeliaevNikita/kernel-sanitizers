/* SPDX-License-Identifier: GPL-2.0 */
#ifndef C_SMC_LOG_H
#define C_SMC_LOG_H

#include <linux/printk.h>

__printf(1, 2) void smc_log_record(const char *fmt, ...);
void smc_log_flush(void);

#define smc_info(fmt, ...) smc_log_record(KERN_INFO fmt, ##__VA_ARGS__)
#define smc_err(fmt, ...) smc_log_record(KERN_ERR fmt, ##__VA_ARGS__)
#define smc_info_ratelimited(fmt, ...) smc_info(fmt, ##__VA_ARGS__)
#define smc_err_ratelimited(fmt, ...) smc_err(fmt, ##__VA_ARGS__)

#endif
