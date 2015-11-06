# door-controller2
A new door controller for a new space, where all the previous hardware is broken and we can't replace it.

This is a daemon to read NFC tags (Mifare Classic 1K) at the door and allow keyholders in.
It mitigates known issues in Mifare so far as is possible.

For a detailed specifiction, see the [wiki](https://wiki.somakeit.org.uk/wiki/The_Door).

## Installing
This is a pyrhon 2 program designed to run on a raspberry pi, though any posixy platform with spi & gpio should work.

* Install python 2.
* Ensure spi is exposed to userspace and you have permission to talk to it (expose /dev/spidev\* as group spi and add the user to the spi group).
* Ensure gpio is exposed to userspace and you have permission to talk to it (expose /sys/class/gpio/\* as group gpio and add the user to the gpio group).
* Clone this repo.
* git submodule init && git submodule update
* pip2 install -U -r requirements.txt
* copy the init script or systemd serivice file to the right directory and edit the values in it.
* Run *service doord enable* (init) or *systemctl enable doord* (systemd)
