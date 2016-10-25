![Logo](https://bitbucket.org/EionRobb/purple-rocketchat/avatar)
# Rocket.Chat Plugin for libpurple #

Adds support for [Rocket.Chat](https://rocket.chat/) to libpurple clients, such as Pidgin.

## Compiling ##
```
#!sh
make && sudo make install
```

### Requirements ###
libpurple, libjson-glib, glib

### Debian-based distros ###
Run the following commands from a terminal

```
#!sh
sudo apt-get install libpurple-dev libjson-glib-dev libglib2.0-dev mercurial make;
hg clone https://bitbucket.org/EionRobb/purple-rocketchat/ && cd purple-rocketchat;
make && sudo make install
```

## Windows Builds ##
Windows nightly builds at https://eion.robbmob.com/librocketchat.dll