#!/usr/bin/env bash

if [[ $SERVER == 1 ]]; then
    read -rp "Would you like to create a new user with root privileges: (y/n) "
    if [[ $REPLY =~ ^[Yy]$ ]]
    then
        read -rp "Enter new user name: " USRNAME
        if [[ -n $USRNAME ]]; then
            sudo useradd -m "$USRNAME" -G sudo --shell /bin/bash
            sudo passwd "$USRNAME"
            sudo passwd -l root
        fi
    fi
fi

