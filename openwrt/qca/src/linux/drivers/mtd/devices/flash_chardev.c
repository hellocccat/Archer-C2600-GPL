/********************************************************************
 *This is flash ioctl for software upgrade and user config.
 *******************************************************************/


#include <linux/init.h>
#include <linux/fs.h>
#include <linux/major.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/mutex.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>
#include <asm/uaccess.h>
#include "../mtdcore.h"

///////////////////////////////////////////////////////////////////////
#define FLASH_READ_SECTOR_SIZE  (4096)
#define FLASH_SECTOR_SIZE       (64 * 1024)
#define FLASH_SIZE_32M          (32 * 1024 * 1024)
#define FLASH_PAGESIZE          (256)
/////////////////////////////////////////////////////////////////////////////////////
/*
 * IOCTL Command Codes
 */
#define TP_FLASH_READ              0x01
#define TP_FLASH_WRITE             0x02
#define TP_FLASH_ERASE             0x03

#define TP_IO_MAGIC                0xB3
#define TP_IO_FLASH_READ           _IOR(TP_IO_MAGIC, TP_FLASH_READ, char)
#define TP_IO_FLASH_WRITE          _IOW(TP_IO_MAGIC, TP_FLASH_WRITE, char)
#define TP_IO_FLASH_ERASE          _IO (TP_IO_MAGIC, TP_FLASH_ERASE)

#define TP_IOC_MAXNR               14

#define flash_major                 239
#define flash_minor                 0

static long tp_flash_ioctl(struct file *file,  unsigned int cmd, unsigned long arg);
static int tp_flash_open(struct inode *inode, struct file *file);

struct file_operations flash_device_op = {
        .owner = THIS_MODULE,
        .unlocked_ioctl = tp_flash_ioctl,
        .open = tp_flash_open,
};

static struct cdev flash_device_cdev = {
        .owner  = THIS_MODULE,
        .ops = &flash_device_op,
};

typedef struct 
{
    u_int32_t addr;     /* flash r/w addr   */
    u_int32_t len;      /* r/w length       */
    u_int8_t* buf;      /* user-space buffer*/
    u_int32_t buflen;   /* buffer length    */
    u_int32_t hasHead;  /* hasHead flag         */
}ARG;

static void mtd_sector_callback(struct erase_info *done)
{
	wait_queue_head_t *wait_q = (wait_queue_head_t *)done->priv;
	wake_up(wait_q);
}

static int mtd_erase_write (struct mtd_info *mtd, unsigned long pos,
			int len, size_t *retlen, const char *buf)
{
	struct erase_info erase;
	DECLARE_WAITQUEUE(waitq, current);
	wait_queue_head_t wait_q;
	int ret;

	/*
	 * First, let's erase the flash block.
	 */

	init_waitqueue_head(&wait_q);
	erase.mtd = mtd;
	erase.callback = mtd_sector_callback;
	erase.addr = pos;
	erase.len = len;
	erase.priv = (u_long)&wait_q;

	set_current_state(TASK_INTERRUPTIBLE);
	add_wait_queue(&wait_q, &waitq);

    *retlen = 0;
	ret = mtd_erase(mtd, &erase);
	if (ret) {
		set_current_state(TASK_RUNNING);
		remove_wait_queue(&wait_q, &waitq);
		printk (KERN_WARNING "mtdblock: erase of region [0x%lx, 0x%x] "
				     "on \"%s\" failed\n",
			pos, len, mtd->name);
		return ret;
	}
	schedule();  /* Wait for erase to finish. */
	remove_wait_queue(&wait_q, &waitq);    
	ret = mtd_write(mtd, pos, len, retlen, buf);
	if (ret)
		return ret;
	if (*retlen != len)
		return -EIO;
	return 0;
}

int nvram_flash_read(struct mtd_info *mtd, u_int8_t *rwBuf, u_int32_t addr, u_int8_t *usrBuf, u_int32_t usrBufLen)
{
    u_int32_t retLen = 0;
    u_int32_t read_len = usrBufLen;
    u_int32_t bytes = FLASH_READ_SECTOR_SIZE;

    /*
     * Note: When 'usrBuf' equals NULL, it means reading to kernel buf 'rwBuf', 
     * so the length should not greater than 64k. Otherwise, 'rwBuf' is used as
     * a temp buffer, we just want to copy to the 'usrBuf'.
     *
     */
    
    if ((usrBuf == NULL && read_len > FLASH_SECTOR_SIZE) || bytes > FLASH_SECTOR_SIZE) {
        printk("flash read length should not greater than 64k each time!\n");
        return -1;
    }

    while (read_len > 0)
    {
        if (bytes >= read_len)
        {
            bytes = read_len;
        }

        if (mtd_read(mtd, addr, bytes, &retLen, rwBuf) < 0)
        {
            printk("mtd_read failed\n");
            return -1;
        }
        
        if (usrBuf != NULL)
        {
            if (copy_to_user(usrBuf, rwBuf, bytes) != 0)
            {
                printk("read copy_to_user failed\n");
                return -1;
            }
            usrBuf += bytes;
        } else {
            rwBuf += bytes;
        }
        
        read_len -= bytes;
        addr += bytes;
    }

    return 0;
}

int nvram_flash_write(struct mtd_info *mtd, u_int8_t *tempData, 
                      u_int32_t hasHead, u_int32_t offset, u_int8_t *data, u_int32_t len)
{
    u_int32_t address = 0;
    u_int32_t headLen = 0;
    u_int32_t endAddr = 0, startAddr = 0;
    u_int8_t *orignData = NULL;
    u_int32_t headData[2] = {len, 0};
    u_int32_t frontLen = 0, tailLen = 0;
    u_int32_t retLen = 0;

    headData[0] = htonl(len);   

    if (hasHead)
    {
        headLen = 2 * sizeof(u_int32_t);
        len += headLen;
    }

    frontLen = offset % FLASH_SECTOR_SIZE;
    tailLen  = (offset + len) % FLASH_SECTOR_SIZE;
    /* first block address */
    address = offset - frontLen;
    /* last uncomplete block address. if none, next block address instead. */
    endAddr = offset + len - tailLen;

    orignData = tempData + FLASH_SECTOR_SIZE;

    if (frontLen > 0 || headLen > 0)/*first block*/
    {
        nvram_flash_read(mtd, orignData, address, NULL, FLASH_SECTOR_SIZE);
        memcpy(tempData, orignData, frontLen);
        
        if (FLASH_SECTOR_SIZE < frontLen + headLen) /* header is in different block */
        {
            headLen = FLASH_SECTOR_SIZE - frontLen;
            /* partition header, first part. */
            memcpy(tempData + frontLen, headData, headLen);

            /***************************************************/
            if (memcmp(orignData, tempData, FLASH_SECTOR_SIZE)) 
            {
                mtd_erase_write(mtd, address, FLASH_SECTOR_SIZE, &retLen, tempData);
            }
            address += FLASH_SECTOR_SIZE;
            /***************************************************/
            nvram_flash_read(mtd, orignData, address, NULL, FLASH_SECTOR_SIZE);
            /* partition header, second part. */
            memcpy(tempData, (u_int8_t*)(headData) + headLen, 8 - headLen);

            if (len - headLen < FLASH_SECTOR_SIZE) /* writen length less than one block */
            {
                headLen = 8 - headLen;
                copy_from_user(tempData + headLen, data, tailLen - headLen); /* data to be writen */
                memcpy(tempData + tailLen, orignData + tailLen, FLASH_SECTOR_SIZE - tailLen);
                data += tailLen - headLen;
            }
            else
            {
                headLen = 8 - headLen;
                copy_from_user(tempData + headLen, data, FLASH_SECTOR_SIZE - headLen);
                data += FLASH_SECTOR_SIZE - headLen;
            }
        }
        else /* normal */
        {
            memcpy(tempData + frontLen, headData, headLen); /* header (if exist) */
            
            if (len + frontLen < FLASH_SECTOR_SIZE) /* write less then a block */
            {
                copy_from_user(tempData + frontLen + headLen, data, len - headLen);
                data += len - headLen;
                /* orginal data */
                memcpy(tempData + frontLen + len,
                         orignData + frontLen + len,
                         FLASH_SECTOR_SIZE - (frontLen + len));
            }
            else
            {
                copy_from_user(tempData + frontLen + headLen, data, FLASH_SECTOR_SIZE - frontLen - headLen);
                /* data to be writen */
                data += FLASH_SECTOR_SIZE - frontLen - headLen;
            }
        }

        /***************************************************/
        if (memcmp(orignData, tempData, FLASH_SECTOR_SIZE))/* context changed */
        {
            mtd_erase_write(mtd, address, FLASH_SECTOR_SIZE, &retLen, tempData);
        }
        address += FLASH_SECTOR_SIZE;
        /***************************************************/
    }

    if (address < endAddr)/* complete blocks in middle */
    {
        startAddr = address;
        while (address < endAddr)
        {
            nvram_flash_read(mtd, orignData, address, NULL, FLASH_SECTOR_SIZE);
            copy_from_user(tempData, data, FLASH_SECTOR_SIZE);
            /***************************************************/
            if (memcmp(orignData, tempData, FLASH_SECTOR_SIZE)) /* context changed */
            {
                mtd_erase_write(mtd, address, FLASH_SECTOR_SIZE, &retLen, tempData);
            }
            address += FLASH_SECTOR_SIZE;
            /***************************************************/
            data += FLASH_SECTOR_SIZE;
        }
    }

    if (address < offset + len) /* last uncomplete block */
    {
        /*printk("[asuka] block at last start %p\n", address);*/
        nvram_flash_read(mtd, orignData, address, NULL, FLASH_SECTOR_SIZE);
        copy_from_user(tempData, data, tailLen); /* firstly, data to be writen */
        memcpy(tempData + tailLen, orignData + tailLen, FLASH_SECTOR_SIZE - tailLen);
        /* secondly, recover orginal data */
        /***************************************************/
        if (memcmp(orignData, tempData, FLASH_SECTOR_SIZE)) /* context changed */
        {
            mtd_erase_write(mtd, address, FLASH_SECTOR_SIZE, &retLen, tempData);
        }
        address += FLASH_SECTOR_SIZE;
        /***************************************************/
    }

    return 0;
}


static long
tp_flash_ioctl(struct file *file,  unsigned int cmd, unsigned long arg)
{
     /* temp buffer for r/w */
    unsigned char *rwBuf = (unsigned char *)kmalloc(FLASH_SECTOR_SIZE * 2, GFP_KERNEL);
    ARG *pArg = (ARG*)arg;
    u_int8_t* usrBuf = pArg->buf;
    u_int32_t usrBufLen = pArg->buflen;
    u_int32_t addr = pArg->addr;
    u_int32_t hasHead = pArg->hasHead;
    extern struct mtd_info *mtd_for_flash_chardev;
    struct mtd_info *mtd = NULL;

    if (NULL == (mtd = mtd_for_flash_chardev)) {
        printk("flash_device_mtd is NULL!\n");
        goto wrong;
    }
    if (rwBuf == NULL)
    {
        printk("rw_buf error!\n");
        goto wrong;
    }
    if (_IOC_TYPE(cmd) != TP_IO_MAGIC)
    {
        printk("cmd type error!\n");
        goto wrong;
    }
    if (_IOC_NR(cmd) > TP_IOC_MAXNR)
    {
        printk("cmd NR error!\n");
        goto wrong;
    }
    
    switch(cmd)
    {
        case TP_IO_FLASH_READ:
        {
            nvram_flash_read(mtd, rwBuf, addr, usrBuf, usrBufLen);
            goto good;
            break; 
        }

        case TP_IO_FLASH_WRITE:
        {
            nvram_flash_write(mtd, rwBuf, hasHead, addr, usrBuf, usrBufLen);
            goto good;
            break;
        }
        
        case  TP_IO_FLASH_ERASE:
        {
            goto good;
            break;
        }
    }

good:
    kfree(rwBuf);
    return 0;
wrong:
    if (rwBuf)
    {
        kfree(rwBuf);
    }

    return -1;
}
        
static int tp_flash_open (struct inode *inode, struct file *filp)
{
    int minor = iminor(inode);
    
    if ((filp->f_mode & 2) && (minor & 1)) {
        printk("You can't open the RO devices RW!\n");
        return -EACCES;
    }
    return 0;
}

#ifdef CONFIG_RAM_SQUASHFS
static struct mtd_info *mtdram_info = NULL;

unsigned int mtd_ram_addr = 0;
unsigned int mtd_ram_size = 0;

EXPORT_SYMBOL(mtd_ram_addr);
EXPORT_SYMBOL(mtd_ram_size);

int ram_squashfs_detect(void)
{
     int index = 0;
     void* mapped = NULL;
     unsigned int size = 0;
     const unsigned int sqsh_magic = 0x73717368;/*'sqsh'*/
     const unsigned int min_size   = 4*1024*1024;
     const unsigned int max_size   = 32*1024*1024;
 
     volatile unsigned int *detect_addrs[] = {(void*)0x44800000};
     
     for (index = 0; index < sizeof(detect_addrs)/sizeof(detect_addrs[0]); index ++) {
         mapped = ioremap((unsigned long)detect_addrs[index], max_size);         
         if (mapped) {
             detect_addrs[index] = mapped;
             /* check magic num && 64-bit squashfs file size. */
             if (le32_to_cpu(detect_addrs[index][0]) == sqsh_magic && 
                 le32_to_cpu(detect_addrs[index][11]) == 0) {
                 size = le32_to_cpu(detect_addrs[index][10]);
                 if (size >= min_size && size <= max_size) {
                     mtd_ram_addr = (unsigned int)mapped;
                     mtd_ram_size = (unsigned int)((size + 0xfff) & (~0xfff));
                     return 1;
                 }
             }
             iounmap(mapped);
         }
     }

     return 0;
}

static int mtdram_read(struct mtd_info *mtd, loff_t from, size_t len,
		size_t *retlen, u_char *buf)
{
	if (from + len > mtd->size)
		return -EINVAL;

	memcpy(buf, mtd->priv + from, len);

	*retlen = len;
	return 0;
}

static void mtdram_cleanup(void)
{
    if (mtdram_info) {
        del_mtd_device(mtdram_info);
        kfree(mtdram_info);
        mtdram_info = NULL;
    }
}

static int mtdram_setup(void)
{
    struct mtd_info *mtd = NULL;

    if (!ram_squashfs_detect()) {
        return 0;
    }

    printk(KERN_NOTICE "############################################################\n");
    printk(KERN_NOTICE "\n%s: booting with mem rootfs@%x/%x.\n\n",
        __func__, mtd_ram_addr, mtd_ram_size);
    printk(KERN_NOTICE "############################################################\n");

    mtd = get_mtd_device_nm("rootfs");
    if (mtd != NULL && mtd != ERR_PTR(-ENODEV)) {
        put_mtd_device(mtd);
        del_mtd_device(mtd);
    } else {
        return -ENODEV;
    }
    
    mtd = kmalloc(sizeof(struct mtd_info), GFP_KERNEL);
    memset(mtd, 0, sizeof(*mtd));

    mtd->name = "rootfs";
    mtd->type = MTD_ROM;
    mtd->flags = MTD_CAP_ROM;
    mtd->size = mtd_ram_size;
    mtd->writesize = 1;
    mtd->priv = (void*)mtd_ram_addr;

    mtd->owner = THIS_MODULE;
    mtd->_read = mtdram_read;

    mtdram_info = mtd;
    if (add_mtd_device(mtd)) {
        return -EIO;
    }

    return 0;
}
#endif

static int __init flash_chrdev_init (void)
{
    dev_t dev;
    int ret = 0;
    int err;
    int bcm_flash_major = flash_major;
    int bcm_flash_minor = flash_minor;

    printk(KERN_WARNING "flash_chrdev : flash_chrdev_init \n");

    if (bcm_flash_major) {
        dev = MKDEV(bcm_flash_major, bcm_flash_minor);
        ret = register_chrdev_region(dev, 1, "flash_chrdev");
    }
    else {
        ret = alloc_chrdev_region(&dev, bcm_flash_minor, 1, "flash_chrdev");
        bcm_flash_major = MAJOR(dev);
    }

    if (ret < 0) {
        printk(KERN_WARNING "flash_chrdev : can`t get major %d\n", bcm_flash_major);
        goto fail;
    }

    cdev_init (&flash_device_cdev, &flash_device_op);
    err = cdev_add(&flash_device_cdev, dev, 1);
    if (err) 
        printk(KERN_NOTICE "Error %d adding flash_chrdev ", err);

#ifdef CONFIG_RAM_SQUASHFS
	mtdram_setup();
#endif

    return 0;

fail:
    return ret;
}

static void __exit flash_chrdev_exit (void)
{
#ifdef CONFIG_RAM_SQUASHFS
	mtdram_cleanup();
#endif
//	unregister_chrdev_region(MKDEV(flash_major, flash_minor), 1);
}


module_init(flash_chrdev_init);
module_exit(flash_chrdev_exit);
//MODULE_LICENSE("GPL");
