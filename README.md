[![Build Status](https://travis-ci.org/somakeit/door-controller2.svg?branch=master)](https://travis-ci.org/somakeit/door-controller2)
# door-controller2
A new door controller for a new space, where all the previous hardware is broken and we can't replace it.

This is a daemon to read NFC tags (Mifare Classic 1K) at the door and allow keyholders in.
It mitigates known issues in Mifare so far as is possible.

For a detailed specifiction, see the [wiki](https://wiki.somakeit.org.uk/wiki/The_Door).

master is unstable, it is suggested that production instances use the most recent release.

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
* Install python-dev, libffi-dev and openssl-dev
* pip2 install -U -r requirements.txt
* Copy doorrc.example to doorrc and replace settings:
    * api_key is the api_secret set in the members area.
    * server_url is the endpoint in the members area, eg. https://members.myhackerspace.org/rfid-tags
    * init_tag_id is the UID of the tag you wish to scan before initialising a new tag for a user, see instructions below and leave as default for now.
    * pull_db_tag_id is the same but for the tag which causes the database to be downloaded from the members area on-demand (the service already does this in the background on a 5 minute loop).
    * keyholder_role_id is the numeric id of the keyholder role in your members are, usually only these people can get in.
    * member_role_id is the id of members, they can only get in if pin 11 is LOW.
    * location_name is free text used for logging
    * mqtt is an optional key which enables publishing of auths to an mqtt broker, it's options are:
        * server required server to connect to
        * port required port to connect to
        * user optional username, default = no username
        * password optional password, default = no password
        * secure optional flag to use tls encryption, default = true. "true" = use authenticated TLS. "false" = do not use TLS. \<path_to_cert> = use TLS and authenticate using this certificate (self signing). There is no option to use TLS with no authentication (insecure mode).
        * topic required base for topic, auths will be published to \<this_path>/\<tag_id>.
* copy the init script or systemd serivice file to the right directory and edit the values in it.
    * Make sure you set a user to run the service and that user is in the gpio and spi groups.
* Running the service at boot:
    * System-V (init):
<pre>update-rc.d doord defaults
update-rc.d doord enable</pre>
    * Systemd:
<pre>systemctl enable doord</pre>

## Setting up the "magic tag" to initialize other tags
* Run the service on the CLI, stop the service if it's running and from the door-controller directory run:
<pre>python2 doord.py</pre>
* Present an NFC tag, it's UID will be printed and doord will claim it is alien.
* Copy the printed uid (eg. "fedcba98") and put it in the doorrc file as the init_tag_id.
* Stop the doord process with ctrl+c.

## Initializing a tag
* With the doord service running, scan the "magic tag" from the above then hold it out the way.
* In the next few seconds, carefully hold a new Mifare Classic 1K NFC tag on the reader until the LED goes from solid to blinking. *Hold it still and be patient.*
* The tag is now initialized and has been sent to the database on the members area server.
    * If the tag did not initialize properly, or the members area server was not available, the keys used to lock this tag will be in your syslog. The tag cannot be assigned to any user and should be erased before re-use, you will need the keys to do this, examine your syslog and *write them on the tag*.
* In the members area, assign the tag to a keyholder.
* Wait about 5 minutes for the door database to update.
* Hold the initialized tag on the reader for about 1 second, the door will open.
