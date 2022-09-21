#!/bin/bash
cargo b --release

ext=$?
if [[ $ext -ne 0 ]]; then
    exit $ext
fi

# provide a subset of the available root privilege => snif traffic
sudo setcap cap_net_admin=eip /home/merry/Documents/trust/target/release/trust
# run the app in background
./target/release/trust &
# actual process
pid=$!


# attribuer l'adresse sur l'interface
# setting up the network
sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0
# kill the process with ctrl c
trap "kill $pid" INT TERM
# wait for the process to finish
wait $pid

# pgrep -af target list of actual process