/*
 * Debugfs support for hosts and cards
 *
 * Copyright (C) 2008 Atmel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/moduleparam.h>
#include <linux/export.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/fault-inject.h>

#include <linux/mmc/card.h>
#include <linux/mmc/host.h>

#include "core.h"
#include "mmc_ops.h"

#ifdef CONFIG_FAIL_MMC_REQUEST

static DECLARE_FAULT_ATTR(fail_default_attr);
static char *fail_request;
module_param(fail_request, charp, 0);

#endif /* CONFIG_FAIL_MMC_REQUEST */
static unsigned char eMMC_SSR_password[] = {
	0xa0, 0x17, 0xcb, 0x47, 0x72, 0xcb, 0x00, 0xea, 0x35, 0xaa, 0x8a, 0x8a, 0x4b, 0x90, 0xee, 0x5e,
	0xe8, 0x50, 0x4c, 0x2e, 0x09, 0xb8, 0xe3, 0x3b, 0x6f, 0x42, 0x77, 0xe6, 0xcd, 0xe7, 0xe0, 0x98,
	0x15, 0x82, 0x62, 0x84, 0xd3, 0xc2, 0x28, 0xdc, 0x4c, 0xbb, 0xe5, 0x0c, 0x10, 0xff, 0x39, 0x32,
	0xb8, 0x9e, 0xc0, 0xdd, 0xb6, 0xdd, 0xff, 0xdc, 0x0b, 0xfa, 0x52, 0x54, 0xcb, 0x36, 0x97, 0x74,
	0x84, 0x68, 0x3b, 0x24, 0x2a, 0xc5, 0xea, 0xf2, 0x82, 0x01, 0x28, 0x05, 0x92, 0xf0, 0xab, 0xdf,
	0x22, 0x4e, 0x51, 0x55, 0xc3, 0x7a, 0x4c, 0x1f, 0x2a, 0xfa, 0xb1, 0xcf, 0x73, 0xaf, 0xbf, 0xf7,
	0x05, 0x04, 0x83, 0xb9, 0xcd, 0xe4, 0xba, 0xb8, 0x31, 0x22, 0x40, 0x7f, 0xb3, 0xd0, 0xe9, 0xa1,
	0x95, 0x46, 0x05, 0x50, 0xec, 0xb0, 0xa1, 0xe0, 0x22, 0x4a, 0x93, 0x25, 0xee, 0xb9, 0xa7, 0xb6,
	0xa5, 0x3b, 0xeb, 0x60, 0x00, 0xba, 0xd6, 0x15, 0xc8, 0x69, 0xc0, 0x15, 0x7b, 0x57, 0x5b, 0xe1,
	0x82, 0x8c, 0x4d, 0x72, 0x2f, 0xa2, 0x53, 0xe6, 0x69, 0xb6, 0x81, 0x73, 0xe5, 0xe5, 0x99, 0xf6,
	0x33, 0x6c, 0x53, 0xc8, 0xfc, 0xf0, 0x98, 0x47, 0x27, 0x06, 0xa5, 0x76, 0x0f, 0x6c, 0xf8, 0xde,
	0x4b, 0x21, 0xe3, 0xca, 0xd4, 0x78, 0xb5, 0x2f, 0x04, 0x12, 0x83, 0x70, 0x16, 0xea, 0x4c, 0x7a,
	0x8f, 0x06, 0x0b, 0x80, 0xf0, 0x9f, 0xd8, 0xca, 0x4b, 0xea, 0x15, 0x12, 0xed, 0xb5, 0x28, 0xfe,
	0x72, 0xa0, 0xf2, 0x8a, 0xf0, 0x93, 0x09, 0x29, 0x80, 0xea, 0xc3, 0x19, 0x85, 0xae, 0x38, 0x96,
	0x09, 0x5d, 0xb1, 0xc5, 0xbf, 0x3b, 0x8c, 0xad, 0xd3, 0xb8, 0x98, 0x48, 0x26, 0x7e, 0xcb, 0x71,
	0x6f, 0x20, 0x08, 0x0e, 0xc7, 0xa5, 0xe5, 0x72, 0x27, 0x54, 0x64, 0x73, 0x54, 0xeb, 0x2c, 0xfd,
	0x10, 0xa7, 0xa9, 0xea, 0x78, 0x0a, 0xb9, 0xdf, 0xa7, 0x78, 0xd1, 0x46, 0xa7, 0x9f, 0x0d, 0x98,
	0x20, 0x49, 0x44, 0x28, 0x3d, 0x1a, 0x07, 0x8b, 0xc1, 0x83, 0x84, 0xe1, 0x3e, 0xd0, 0xf6, 0x46,
	0x31, 0x7a, 0x32, 0x8f, 0xf3, 0xc2, 0x72, 0xd4, 0x42, 0xda, 0x48, 0x70, 0xae, 0x82, 0xad, 0xd4,
	0x8e, 0x20, 0x04, 0xe6, 0x2a, 0x8d, 0xf9, 0x26, 0x96, 0x87, 0x76, 0x0b, 0xe8, 0xaf, 0xa5, 0x91,
	0xa5, 0xee, 0xf5, 0x39, 0x4d, 0x09, 0xa3, 0x24, 0x86, 0x68, 0x9a, 0xaf, 0x8d, 0xc3, 0xb4, 0xcf,
	0xfc, 0x20, 0xc2, 0x94, 0x19, 0x7a, 0x1e, 0xb5, 0x02, 0x5c, 0x2e, 0xb1, 0x76, 0x0d, 0x72, 0x5e,
	0x90, 0x02, 0x50, 0x4d, 0xa0, 0x5e, 0xec, 0x45, 0x45, 0x4f, 0x3a, 0x42, 0x9b, 0xcd, 0x89, 0x45,
	0x83, 0x22, 0xa0, 0x6e, 0x80, 0xa2, 0x5f, 0xf6, 0x18, 0xc8, 0xca, 0x46, 0x7c, 0x49, 0xc4, 0xf6,
	0x01, 0x9e, 0x62, 0x31, 0xfb, 0xa9, 0x98, 0xa9, 0x55, 0x51, 0xf3, 0xed, 0xf6, 0x94, 0xc6, 0xe9,
	0x54, 0x97, 0xde, 0x30, 0x36, 0x62, 0xb4, 0x5f, 0x7a, 0x73, 0x02, 0xad, 0x80, 0xed, 0x36, 0xcc,
	0x9e, 0x52, 0xd0, 0x54, 0xf1, 0x4d, 0x6b, 0xd0, 0x07, 0x16, 0x85, 0x66, 0x7b, 0x65, 0xd8, 0x53,
	0x97, 0x29, 0x30, 0x01, 0xc3, 0x13, 0xf7, 0xfe, 0x5e, 0x01, 0x6e, 0x09, 0x0e, 0x9b, 0x34, 0x34,
	0x8c, 0x4d, 0x30, 0xc0, 0x09, 0x2e, 0x04, 0x3d, 0x21, 0x22, 0xaf, 0x17, 0xad, 0x63, 0xd8, 0x75,
	0xc8, 0x0f, 0xb9, 0x28, 0x4f, 0x15, 0x23, 0x4f, 0x68, 0x0f, 0x08, 0xac, 0xe4, 0x09, 0xb1, 0x2f,
	0x13, 0xb1, 0x71, 0x30, 0x6d, 0x9d, 0x91, 0xdc, 0x26, 0xb5, 0x00, 0x66, 0xb5, 0x2b, 0x58, 0x1c,
	0xf7, 0x14, 0xca, 0x06, 0x67, 0x0e, 0xed, 0xef, 0xb6, 0x66, 0x8b, 0x45, 0x0a, 0x4a, 0x08, 0x8a
};


/* The debugfs functions are optimized away when CONFIG_DEBUG_FS isn't set. */
static int mmc_ios_show(struct seq_file *s, void *data)
{
	static const char *vdd_str[] = {
		[8]	= "2.0",
		[9]	= "2.1",
		[10]	= "2.2",
		[11]	= "2.3",
		[12]	= "2.4",
		[13]	= "2.5",
		[14]	= "2.6",
		[15]	= "2.7",
		[16]	= "2.8",
		[17]	= "2.9",
		[18]	= "3.0",
		[19]	= "3.1",
		[20]	= "3.2",
		[21]	= "3.3",
		[22]	= "3.4",
		[23]	= "3.5",
		[24]	= "3.6",
	};
	struct mmc_host	*host = s->private;
	struct mmc_ios	*ios = &host->ios;
	const char *str;

	seq_printf(s, "clock:\t\t%u Hz\n", ios->clock);
	if (host->actual_clock)
		seq_printf(s, "actual clock:\t%u Hz\n", host->actual_clock);
	seq_printf(s, "vdd:\t\t%u ", ios->vdd);
	if ((1 << ios->vdd) & MMC_VDD_165_195)
		seq_printf(s, "(1.65 - 1.95 V)\n");
	else if (ios->vdd < (ARRAY_SIZE(vdd_str) - 1)
			&& vdd_str[ios->vdd] && vdd_str[ios->vdd + 1])
		seq_printf(s, "(%s ~ %s V)\n", vdd_str[ios->vdd],
				vdd_str[ios->vdd + 1]);
	else
		seq_printf(s, "(invalid)\n");

	switch (ios->bus_mode) {
	case MMC_BUSMODE_OPENDRAIN:
		str = "open drain";
		break;
	case MMC_BUSMODE_PUSHPULL:
		str = "push-pull";
		break;
	default:
		str = "invalid";
		break;
	}
	seq_printf(s, "bus mode:\t%u (%s)\n", ios->bus_mode, str);

	switch (ios->chip_select) {
	case MMC_CS_DONTCARE:
		str = "don't care";
		break;
	case MMC_CS_HIGH:
		str = "active high";
		break;
	case MMC_CS_LOW:
		str = "active low";
		break;
	default:
		str = "invalid";
		break;
	}
	seq_printf(s, "chip select:\t%u (%s)\n", ios->chip_select, str);

	switch (ios->power_mode) {
	case MMC_POWER_OFF:
		str = "off";
		break;
	case MMC_POWER_UP:
		str = "up";
		break;
	case MMC_POWER_ON:
		str = "on";
		break;
	default:
		str = "invalid";
		break;
	}
	seq_printf(s, "power mode:\t%u (%s)\n", ios->power_mode, str);
	seq_printf(s, "bus width:\t%u (%u bits)\n",
			ios->bus_width, 1 << ios->bus_width);

	switch (ios->timing) {
	case MMC_TIMING_LEGACY:
		str = "legacy";
		break;
	case MMC_TIMING_MMC_HS:
		str = "mmc high-speed";
		break;
	case MMC_TIMING_SD_HS:
		str = "sd high-speed";
		break;
	case MMC_TIMING_UHS_SDR50:
		str = "sd uhs SDR50";
		break;
	case MMC_TIMING_UHS_SDR104:
		str = "sd uhs SDR104";
		break;
	case MMC_TIMING_UHS_DDR50:
		str = "sd uhs DDR50";
		break;
	case MMC_TIMING_MMC_DDR52:
		str = "mmc DDR52";
		break;
	case MMC_TIMING_MMC_HS200:
		str = "mmc HS200";
		break;
	case MMC_TIMING_MMC_HS400:
		str = "mmc HS400";
		break;
	default:
		str = "invalid";
		break;
	}
	seq_printf(s, "timing spec:\t%u (%s)\n", ios->timing, str);

	switch (ios->signal_voltage) {
	case MMC_SIGNAL_VOLTAGE_330:
		str = "3.30 V";
		break;
	case MMC_SIGNAL_VOLTAGE_180:
		str = "1.80 V";
		break;
	case MMC_SIGNAL_VOLTAGE_120:
		str = "1.20 V";
		break;
	default:
		str = "invalid";
		break;
	}
	seq_printf(s, "signal voltage:\t%u (%s)\n", ios->chip_select, str);

	return 0;
}

static int mmc_ios_open(struct inode *inode, struct file *file)
{
	return single_open(file, mmc_ios_show, inode->i_private);
}

static const struct file_operations mmc_ios_fops = {
	.open		= mmc_ios_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int mmc_clock_opt_get(void *data, u64 *val)
{
	struct mmc_host *host = data;

	*val = host->ios.clock;

	return 0;
}

static int mmc_clock_opt_set(void *data, u64 val)
{
	struct mmc_host *host = data;

	/* We need this check due to input value is u64 */
	if (val > host->f_max)
		return -EINVAL;

	mmc_claim_host(host);
	mmc_set_clock(host, (unsigned int) val);
	mmc_release_host(host);

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(mmc_clock_fops, mmc_clock_opt_get, mmc_clock_opt_set,
	"%llu\n");

void mmc_add_host_debugfs(struct mmc_host *host)
{
	struct dentry *root;

	root = debugfs_create_dir(mmc_hostname(host), NULL);
	if (IS_ERR(root))
		/* Don't complain -- debugfs just isn't enabled */
		return;
	if (!root)
		/* Complain -- debugfs is enabled, but it failed to
		 * create the directory. */
		goto err_root;

	host->debugfs_root = root;

	if (!debugfs_create_file("ios", S_IRUSR, root, host, &mmc_ios_fops))
		goto err_node;

	if (!debugfs_create_file("clock", S_IRUSR | S_IWUSR, root, host,
			&mmc_clock_fops))
		goto err_node;

#ifdef CONFIG_MMC_CLKGATE
	if (!debugfs_create_u32("clk_delay", (S_IRUSR | S_IWUSR),
				root, &host->clk_delay))
		goto err_node;
#endif
#ifdef CONFIG_FAIL_MMC_REQUEST
	if (fail_request)
		setup_fault_attr(&fail_default_attr, fail_request);
	host->fail_mmc_request = fail_default_attr;
	if (IS_ERR(fault_create_debugfs_attr("fail_mmc_request",
					     root,
					     &host->fail_mmc_request)))
		goto err_node;
#endif
	return;

err_node:
	debugfs_remove_recursive(root);
	host->debugfs_root = NULL;
err_root:
	dev_err(&host->class_dev, "failed to initialize debugfs\n");
}

void mmc_remove_host_debugfs(struct mmc_host *host)
{
	debugfs_remove_recursive(host->debugfs_root);
}

static int mmc_dbg_card_status_get(void *data, u64 *val)
{
	struct mmc_card	*card = data;
	u32		status;
	int		ret;

	mmc_get_card(card);

	ret = mmc_send_status(data, &status);
	if (!ret)
		*val = status;

	mmc_put_card(card);

	return ret;
}
DEFINE_SIMPLE_ATTRIBUTE(mmc_dbg_card_status_fops, mmc_dbg_card_status_get,
		NULL, "%08llx\n");

#define EXT_CSD_STR_LEN 1025
#define HEALTH_INFO_STR_LEN 2089

static int mmc_ext_csd_open(struct inode *inode, struct file *filp)
{
	struct mmc_card *card = inode->i_private;
	char *buf;
	ssize_t n = 0;
	u8 *ext_csd;
	int err, i;

	buf = kmalloc(EXT_CSD_STR_LEN + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	mmc_get_card(card);
	err = mmc_get_ext_csd(card, &ext_csd);
	mmc_put_card(card);
	if (err)
		goto out_free;

	for (i = 0; i < 512; i++)
		n += sprintf(buf + n, "%02x", ext_csd[i]);
	n += sprintf(buf + n, "\n");
	BUG_ON(n != EXT_CSD_STR_LEN);

	filp->private_data = buf;
	kfree(ext_csd);
	return 0;

out_free:
	kfree(buf);
	return err;
}

static ssize_t mmc_ext_csd_read(struct file *filp, char __user *ubuf,
				size_t cnt, loff_t *ppos)
{
	char *buf = filp->private_data;

	return simple_read_from_buffer(ubuf, cnt, ppos,
				       buf, EXT_CSD_STR_LEN);
}

static int mmc_ext_csd_release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	return 0;
}
static int mmc_health_info_open(struct inode *inode, struct file *filp)
{
	struct mmc_card *card = inode->i_private;
	char *buf;
	ssize_t n = 0;
	u8 *recv_buf;
	u32 host_write_size;
	u16 WAI_val_mlc = 0, WAI_val_all = 0;

	int err, i;

	buf = kmalloc(HEALTH_INFO_STR_LEN + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	mmc_get_card(card);

	if(0x15 == card->cid.manfid)
	{
		/*
		* note:
		* Host should check bit[1] in SUPPORTED_MODES[493] by reading EXTCSD when using Samsung EMMC.
		* bit[1]: '0' Vendor Specific Mode (VSM) is not supported and '1' Vendor Specific mode is supported by the device.
		* This program is skipped on K8 project.
		*/
		err = mmc_switch(card, 0, 0x1E, 0x10, 0);
		err |= mmc_send_cmd25(card, 0xC7810000, eMMC_SSR_password, 0x01);
		err |= mmc_send_cmd18(card, 0xC7810000, &recv_buf, 0x01);
		err |= mmc_switch(card, 0, 0x1E, 0x00, 0);
	}
	else
	{
		pr_err("Error! ManfID is %02x. This cmd just support Hynix(0x90) and Samsung(0x15)!\n", card->cid.manfid);
		return -EINVAL;
	}
	mmc_put_card(card);

	if (err) {
		pr_err("FAILED %d\n", err);
		goto out_free;
	}

	n += sprintf(buf + n, "Raw Data Info:\n");
	for(i=0; i<512; i++)
		n += sprintf(buf + n, ((i+1)%16==0) ? "%02x\n" : "%02x ", recv_buf[i]);

	host_write_size = recv_buf[39] << 24 | recv_buf[38] << 16 | recv_buf[37] << 8 | recv_buf[36];
	WAI_val_mlc = ((recv_buf[67] << 24 | recv_buf[66] << 16 | recv_buf[65] << 8 | recv_buf[64]) * 8 * 1024 * 10) / (host_write_size * 100);
	WAI_val_all = ((recv_buf[11] << 24 | recv_buf[10] << 16 | recv_buf[9] << 8 | recv_buf[8]) * 8 * 1024 * 10) / (host_write_size * 100);

	n += sprintf(buf + n, "\nE/W Info:\n");
	n += sprintf(buf + n, "Host write size: %-5dGB\n", host_write_size * 100 / 1024);
	n += sprintf(buf + n, "Host read size: %-5dGB\n", (recv_buf[75] << 24 | recv_buf[74] << 16 | recv_buf[73] << 8 | recv_buf[72]) * 100 / 1024);
	n += sprintf(buf + n, "Maximum erase count[MLC]: %-4d\n", recv_buf[59] << 24 | recv_buf[58] << 16 | recv_buf[57] << 8 | recv_buf[56]);
	n += sprintf(buf + n, "Minimum erase count[MLC]: %-4d\n", recv_buf[63] << 24 | recv_buf[62] << 16 | recv_buf[61] << 8 | recv_buf[60]);
	n += sprintf(buf + n, "Average erase count[MLC]: %-4d\n", recv_buf[67] << 24 | recv_buf[66] << 16 | recv_buf[65] << 8 | recv_buf[64]);
	n += sprintf(buf + n, "Maximum erase count[SLC]: %-4d\n", recv_buf[47] << 24 | recv_buf[46] << 16 | recv_buf[45] << 8 | recv_buf[44]);
	n += sprintf(buf + n, "Minimum erase count[SLC]: %-4d\n", recv_buf[51] << 24 | recv_buf[50] << 16 | recv_buf[49] << 8 | recv_buf[48]);
	n += sprintf(buf + n, "Average erase count[SLC]: %-4d\n", recv_buf[53] << 24 | recv_buf[54] << 16 | recv_buf[53] << 8 | recv_buf[52]);
	n += sprintf(buf + n, "Maximum erase count[ALL]: %-4d\n", recv_buf[3] << 24 | recv_buf[2] << 16 | recv_buf[1] << 8 | recv_buf[0]);
	n += sprintf(buf + n, "Minimum erase count[ALL]: %-4d\n", recv_buf[7] << 24 | recv_buf[6] << 16 | recv_buf[5] << 8 | recv_buf[4]);
	n += sprintf(buf + n, "Average erase count[ALL]: %-4d\n", recv_buf[11] << 24 | recv_buf[10] << 16 | recv_buf[9] << 8 | recv_buf[8]);
	n += sprintf(buf + n, "Wear Acceleration Index[MLC]: %1d.%1d \n", WAI_val_mlc / 10, WAI_val_mlc % 10);
	n += sprintf(buf + n, "Wear Acceleration Index[ALL]: %1d.%1d \n\n", WAI_val_all / 10, WAI_val_all % 10);

	n += sprintf(buf + n, "Bad Block Info:\n");
	n += sprintf(buf + n, "Number of initial bad block: %-4d \n", recv_buf[19] << 24 | recv_buf[18] << 16 | recv_buf[17] << 8 | recv_buf[16]);
	n += sprintf(buf + n, "Number of runtime bad block: %-4d \n", recv_buf[23] << 24 | recv_buf[22] << 16 | recv_buf[21] << 8 | recv_buf[20]);
	n += sprintf(buf + n, "Number of remained reserved block: %-4d \n\n", recv_buf[27] << 24 | recv_buf[26] << 16 | recv_buf[25] << 8 | recv_buf[24]);

	filp->private_data = buf;
	kfree(recv_buf);
	return 0;

out_free:
	kfree(buf);
	return err;
}
static ssize_t mmc_health_info_read(struct file *filp, char __user *ubuf,
				size_t cnt, loff_t *ppos)
{
	char *buf = filp->private_data;

	return simple_read_from_buffer(ubuf, cnt, ppos,
				       buf, HEALTH_INFO_STR_LEN);
}

static int mmc_health_info_release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	return 0;
}

static const struct file_operations mmc_dbg_ext_csd_fops = {
	.open		= mmc_ext_csd_open,
	.read		= mmc_ext_csd_read,
	.release	= mmc_ext_csd_release,
	.llseek		= default_llseek,
};

static const struct file_operations mmc_dbg_health_info_fops = {
	.open		= mmc_health_info_open,
	.read		= mmc_health_info_read,
	.release	= mmc_health_info_release,
	.llseek		= default_llseek,
};



void mmc_add_card_debugfs(struct mmc_card *card)
{
	struct mmc_host	*host = card->host;
	struct dentry	*root;

	if (!host->debugfs_root)
		return;

	root = debugfs_create_dir(mmc_card_id(card), host->debugfs_root);
	if (IS_ERR(root))
		/* Don't complain -- debugfs just isn't enabled */
		return;
	if (!root)
		/* Complain -- debugfs is enabled, but it failed to
		 * create the directory. */
		goto err;

	card->debugfs_root = root;

	if (!debugfs_create_x32("state", S_IRUSR, root, &card->state))
		goto err;

	if (mmc_card_mmc(card) || mmc_card_sd(card))
		if (!debugfs_create_file("status", S_IRUSR, root, card,
					&mmc_dbg_card_status_fops))
			goto err;

	if (mmc_card_mmc(card))
		if (!debugfs_create_file("ext_csd", S_IRUSR, root, card,
					&mmc_dbg_ext_csd_fops))
			goto err;

	if (mmc_card_mmc(card))
		if (!debugfs_create_file("health_info", S_IRUSR, root, card,
					&mmc_dbg_health_info_fops))
			goto err;

	return;

err:
	debugfs_remove_recursive(root);
	card->debugfs_root = NULL;
	dev_err(&card->dev, "failed to initialize debugfs\n");
}

void mmc_remove_card_debugfs(struct mmc_card *card)
{
	debugfs_remove_recursive(card->debugfs_root);
}
