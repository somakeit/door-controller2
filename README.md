[![Build Status](https://travis-ci.org/somakeit/door-controller2.svg?branch=master)](https://travis-ci.org/somakeit/door-controller2)
# door-controller2
A new door controller for a new space, where all the previous hardware is broken and we can't replace it.

This is a daemon to read NFC tags (Mifare Classic 1K) at the door and allow keyholders in.
It mitigates known issues in Mifare so far as is possible.

For a detailed specifiction, see the [wiki](https://wiki.somakeit.org.uk/wiki/The_Door).

## Installing
This is a pyrhon 2 program designed to run on a raspberry pi, though any posixy platform with spi & gpio should work.

* Make the following connections on the pi pins:
    * 15 - Door strike, held HIGH for door open, otherwise LOW.
    * 18 - LED, an LED that is useful for users to see while scanning tgs.
    * 11 - Switch (optional), a "space open" switch, held HIGH by internal pull-up, when connected to GND by switch, members and keyholders may unlock the door, otherwise just keyholders.
    * RC522 board:
        * 1 - 3V3
        * 22 - RST
        * Any - Ground
        * 21 - MISO
        * 19 - MOSI
        * 23 - SCK
        * 24 - SDA
        * not-connected - IRQ
* Install python 2.
* Ensure spi is exposed to userspace and you have permission to talk to it (expose /dev/spidev\* as group spi and add the user to the spi group).
* Ensure gpio is exposed to userspace and you have permission to talk to it (expose /sys/class/gpio/\* as group gpio and add the user to the gpio group).
* Clone this repo.
* git submodule init && git submodule update
* Install libffi-dev and openssl-dev
* pip2 install -U -r requirements.txt
* Copy doorrc.example to doorrc and replace settings:
    * api_key is the api_secret set in the members area.
    * server_url is the endpoint in the members area, eg. https://members.myhackerspace.org/rfid-tags
    * init_tag_id is the UID of the tag you wish to scan before initialising a new tag for a user. THe UID is written exactly as this program logs to syslog when you scan an unregistered card.
    * pull_db_tag_id is the same but for the tag which causes the database to be downloaded from the members area on-demand (it does it in the background on a 5 minute loop too).
    * keyholder_role_id is the numeric id of the keyholder role in your members are, only these people can get in.
    * member_role_id is the id of members, they can only get in if pin 11 is LOW.
    * location_name is free text used for logging
* copy the init script or systemd serivice file to the right directory and edit the values in it.
* Run *service doord enable* (init) or *systemctl enable doord* (systemd)
