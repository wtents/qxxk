/*
 *  QCA HyFi Netfilter
 *
 * Copyright (c) 2012 The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2, as published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include "hyfi_netfilter.h"
#include "hyfi_bridge.h"
#include "hyfi_netlink.h"
#include "hyfi_notify.h"
#include "hyfi_fdb.h"

/* Macro definitions */
#define LKM_AUTHOR          "Hai Shalom and Miaoqing Pan"
#define LKM_DESCRIPTION     "QCA Hy-Fi Bridging"

extern int mc_init(void);
extern void mc_exit(void);

static int __init hyfi_init(void)
{
	int ret;

	/* Initialize the bridge device */
	if ((ret = hyfi_bridge_init())) {
		goto out;
	}

	if ((ret = mc_init())) {
		goto out;
	}

	if ((ret = hyfi_netfilter_init())) {
		goto out;
	}

	if ((ret = hyfi_notify_init())) {
		goto out;
	}

	if ((ret = hyfi_netlink_init())) {
		goto out;
	}

	out: printk("QCA Hy-Fi netfilter installation: %s\n",
			ret ? "FAILED" : "OK");

	return ret;
}

static void __exit hyfi_exit(void)
{
    mc_exit();

	hyfi_bridge_fini();
	hyfi_netfilter_fini();
	hyfi_netlink_fini();
    hyfi_notify_fini();

	printk( "QCA Hy-Fi netfilter uninstalled\n" );
}

module_init(hyfi_init);
module_exit(hyfi_exit);

/*
 * Define the module’s license. Important!
 */

MODULE_LICENSE("GPL v2");

/*
 * Optional definitions
 */

MODULE_AUTHOR(LKM_AUTHOR);
/* The author’s name */
MODULE_DESCRIPTION(LKM_DESCRIPTION);
/* The module description */

/*
 * API the module exports to other modules
 */
