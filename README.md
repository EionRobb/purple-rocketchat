![Logo](https://bitbucket.org/EionRobb/purple-rocketchat/avatar)
# Rocket.Chat Plugin for libpurple #

Adds support for [Rocket.Chat](https://rocket.chat/) to libpurple clients, such as Pidgin.

## Compiling ##
```
#!sh
make && sudo make install
```

### Requirements ###
libpurple, libjson-glib, glib, libmarkdown2 aka discount

### Debian-based distros ###
Run the following commands from a terminal

```
#!sh
sudo apt-get install libpurple-dev libjson-glib-dev libglib2.0-dev mercurial make libmarkdown2-dev;
hg clone https://bitbucket.org/EionRobb/purple-rocketchat/ && cd purple-rocketchat;
make && sudo make install
```

### Fedora-based distros ###
Run the following commands from a terminal

```
#!sh
dnf install libpurple-devel.x86_64 libmarkdown-devel.x86_64 json-glib-devel.x86_64 glib2.x86_64
hg clone https://bitbucket.org/EionRobb/purple-rocketchat/ && cd purple-rocketchat;
make && sudo make install
```

## Windows Builds ##
Windows nightly builds at https://eion.robbmob.com/librocketchat.dll - copy to Program Files\Pidgin\plugins

## How to Use ##
* Install the plugin (see above)
* Add your account (Accounts->Manage Accounts->Add):
+ ![rocket chat add account.png](https://bitbucket.org/repo/gEprjk/images/3996485994-rocket%20chat%20add%20account.png)
* Open the room list (Tools->Plugins):
+ ![rocket chat roomlist.png](https://bitbucket.org/repo/gEprjk/images/4264884259-rocket%20chat%20roomlist.png)
* Click the "Get List" button:
+ ![rocket chat roomlist 2.png](https://bitbucket.org/repo/gEprjk/images/2591558922-rocket%20chat%20roomlist%202.png)
* Add the chat to your buddy list
+ ![rocket chat add room.png](https://bitbucket.org/repo/gEprjk/images/853635018-rocket%20chat%20add%20room.png)