vusbf-Framework
===========
             _        _                  _               _     
     __   __(_) _ __ | |_  _   _   __ _ | |  _   _  ___ | |__  
     \ \ / /| || '__|| __|| | | | / _` || | | | | |/ __|| '_ \ 
      \ V / | || |   | |_ | |_| || (_| || | | |_| |\__ \| |_) |
       \_/  |_||_|    \__| \__,_| \__,_||_|  \__,_||___/|_.__/ 
                                       
       / _| _   _  ____ ____ ___  _ __ 
      | |_ | | | ||_  /|_  // _ \| '__|
      |  _|| |_| | / /  / /|  __/| |   
      |_|   \__,_|/___|/___|\___||_|   

A KVM/QEMU based USB-fuzzing framework.

Sergej Schumilo, OpenSource Security Spenneberg 2014

Version: 0.1

GENERAL
===========


A USB-fuzzer which takes advantage of massive usage of virtual machines and also offers high reproducibility.

This framework was initially released at Black Hat Europe 2014.

https://www.blackhat.com/docs/eu-14/materials/eu-14-Schumilo-Dont-Trust-Your-USB-How-To-Find-Bugs-In-USB-Device-Drivers-wp.pdf


This software is under heavy development. Get a copy of the actual version at github:

http://www.github.com/schumilo

This software is licensed under GPLv2.

** Stay tuned! We are working on some bugfixes and new features! **


This framework provides:
- USB-fuzzing in practical time frames
- multiprocessing and clustering
- export sequences of payloads and replay them for debugging or investigation
- XML-based dynamic testcase generating 
- expandable by writing new testcases, USB-emulators or monitoring-modules

vUSBf was written in python2 and requires the Scapy-framework.

PREPARATIONS
==========

First of all we've to build a compatible version of QEMU! Get the newest version of QEMU and usbredir:


QEMU:           http://www.qemu.org


usbredir:       https://github.com/SPICE/usbredir



Be sure that you compile QEMU with the option "usb_redir" and you also patch the file /hw/usb/redirection.c.
If you're using the QEMU version 2.1.1, you can apply our patch (qemu-2.1.1.patch).

vUSBf requires some prepared QCOW2-images for fuzzing!
At first you've to create a QCOW2-image for your virtual machine. You can do this by using the following command:

    qemu-img create -f qcow2 vm.qcow2 10G

Install your preferred operating system on that image. You've to configure a TTY which is available at the (virtual) serial port.

The next step is to create a backing-file (overlay which contains all of the future delta) and an image which will contain a snapshot of the VM (the size should be larger than your virtual memory you have configured):

    qemu-img create -b vm.img -f qcow2 overlay.qcow2
    qemu-img create -f qcow2 ram.qcow2 1G

Start your VM with the following command, wait until the kernel is loaded, log in and change the verbosity of printk by entering "echo '7' > /proc/sys/kernel/printk".
Now you can take a snapshot by entering the QEMU console (press ctrl+a and c) and type savevm <name>. You should start the VM by the following command:

    qemu-system-x86_64 --enable-kvm -m 1024 -hdb ram.qcow2 -hda overlay.qcow2 -serial mon:stdio -device nec-usb-xhci -device usb-redir,chardev=usbchardev,debug=0

Create a customized configuration in the "vusbf/configurations/" folder. You'll find there some examples. Modify the following information:

        - location of your QEMU-binary you want to use
        - KVM support (write yes or no)
        - size of your memory (the unit is MB)
        - location of your ram-file
        - location of your overlay-file
        - location where your overlay duplicates should be stored
        - configured USB-host-controller (if you have no idea just write nec-usb-xhci)
        - some extra parameters for QEMU (if you need some)
        - the name of the snapshot

That's all. Now your VM is ready for some fuzzing.

RUNNING VUSBF
==========

Take a look at help.txt or run vusbf with the parameter -h for help :-)


BUGS
==========

This version of the software just represents an early concept. There are some known bugs like (rare) deadlocks by using the python subprocess module for starting QEMU and the slow and memory-hungry generating of testcases. YMMV. We are working on these issues, so be sure you are using the newest version. Moreover the lack of USB-emulators is another point we are working on.

Furthermore some inline comments were written in my native language (german). They will be translated later ;-) and the code will be more documented!

Comrade-in-arms are welcome :-)! 
There is a lot of work to do!


CONTACT
==========

Feel free to send us an email:

<schumilo@fh-muenster.de>

<info@os-s.net>



