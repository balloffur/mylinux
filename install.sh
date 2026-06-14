#!/bin/bash

function update_system() {
    sudo apt-get update
    sudo apt-get upgrade -y
}

function install_git() {
    if ! command -v git >/dev/null 2>&1; then
        sudo apt-get install -y git
    fi
}

function fetch_repo() {
    if [ ! -d "$HOME/.mylinux" ]; then
        git clone https://github.com/balloffur/mylinux.git /tmp/mylinux_tmp
        mv /tmp/mylinux_tmp/.mylinux "$HOME/.mylinux"
        rm -rf /tmp/mylinux_tmp
    fi
}

function fetch_small_things() {
    if [ ! -d "$HOME/.mylinux/small_things" ]; then
        git clone https://github.com/balloffur/small_things.git "$HOME/.mylinux/small_things"
    fi
}

function install_deps() {
    if [ -f "$HOME/.mylinux/install/depend" ]; then
        sudo apt-get install -y $(cat "$HOME/.mylinux/install/depend")
    fi
}

function setup_bashrc() {
    if [ -f "$HOME/.mylinux/install/bashrc_addition" ]; then
        cat "$HOME/.mylinux/install/bashrc_addition" >> "$HOME/.bashrc"
    fi
}

function setup_aliases() {
    if [ -f "$HOME/.mylinux/install/.bash_aliases" ]; then
        cp "$HOME/.mylinux/install/.bash_aliases" "$HOME/.bash_aliases"
    fi
}

function setup_permissions() {
    if [ -d "$HOME/.mylinux/scripts" ]; then
        chmod -R +x "$HOME/.mylinux/scripts"
    fi
    if [ -d "$HOME/.mylinux/small_things" ]; then
        chmod -R +x "$HOME/.mylinux/small_things"
    fi
}

function install_full() {
    if [ "$1" == "full" ] && [ -f "$HOME/.mylinux/install/full_soft" ]; then
        bash "$HOME/.mylinux/install/full_soft"
    fi
}

function main() {
    update_system
    install_git
    fetch_repo
    fetch_small_things
    install_deps
    setup_bashrc
    setup_aliases
    setup_permissions
    install_full "$1"
}

main "$@"
