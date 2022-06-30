![Logo](https://github.com/EionRobb/purple-rocketchat/raw/master/rocketchat48.png)
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

```shell
#!sh
sudo apt-get install libpurple-dev libjson-glib-dev libglib2.0-dev git make libmarkdown2-dev;
git clone https://github.com/EionRobb/purple-rocketchat && cd purple-rocketchat;
make && sudo make install
```

### Ubuntu
```shell
sudo apt install purple-rocketchat
```

### Fedora-based distros ###
Run the following commands from a terminal

```shell
#!sh
dnf install libpurple-devel.x86_64 libmarkdown-devel.x86_64 json-glib-devel.x86_64 glib2.x86_64
git clone https://github.com/EionRobb/purple-rocketchat && cd purple-rocketchat;
make && sudo make install
```

## Windows Builds ##
Windows nightly builds at https://eion.robbmob.com/librocketchat.dll - copy to `Program Files (x86)\Pidgin\plugins`

You'll also need [libjson-glib-1.0.dll](https://eion.robbmob.com/libjson-glib-1.0.dll) in your `Program Files (x86)\Pidgin` directory (*not the plugins subdirectory*) if you don't already have the Skype/Facebook/Steam/other plugin installed

## How to Use ##
* Install the plugin (see above)
* Add your account (Accounts->Manage Accounts->Add)
* Open the room list (Tools->Room List...)
* Click the "Get List" button
* Add the chat to your buddy list

## Auth Issues? ##
If you're getting "Bad Username/Password" errors, and you're definitely sure that you're using the right username/password, or if your Rocket.Chat instance uses a 3rd party for authentication (eg Ookla, Google or Microsoft) then you'll need to make a Personal Access Token:
* In the official Rocket.Chat app, click on your profile then  My Account -> Personal Access Token
* Add a new PAT without 2FA
* Copy-paste the token and user-id fields into Tools -> Accounts -> {Your rocket.chat account} -> Advanced -> Personal Access Token (and User ID) fields in Pidgin
More info about PATs at https://docs.rocket.chat/guides/user-guides/user-panel/managing-your-account/personal-access-token


## Like this plugin? ##
Say "Thanks" by [sending $1](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=PZMBF2QVF69GA)
