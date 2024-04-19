# wirething-poc

This proof of concept uses the [ntfy](https://ntfy.sh) service,
[STUNTMAN](https://www.stunprotocol.org) and [wireguard](https://www.wireguard.com)
to connect without any login two devices behind NAT.

## Dependencies

Run the command below to see if anything is missing:

    ./wirething-poc.sh deps

Then download and unpack https://github.com/pufferffish/wireproxy/releases.

    os="darwin"
    arch="amd64"
    version="v1.0.9"

    wget "https://github.com/pufferffish/wireproxy/releases/download/${version}/wireproxy_${os}_${arch}.tar.gz"
    tar -xzvf "wireproxy_${os}_${arch}.tar.gz"

## Testing locally

    # Terminal 1

    ln -nfs "<unpacked_path>/wireproxy" ./wireproxy
    export WIREPROXY_COMMAND="${PWD}/wireproxy"
    export WIREPROXY_SOCKS5_BIND="disabled"

    ./wirething-poc.sh cli new local alice
    ./wirething-poc.sh cli export local alice

    ./wirething-poc.sh cli new remote bob
    ./wirething-poc.sh cli export remote bob

    ./wirething-poc.sh cli add local ./bob.peer
    ./wirething-poc.sh cli add remote ./alice.peer

    # Terminal 2

    WT_STORE_ENABLED=true WT_DOMAIN=local ./wirething-poc.sh

    # Terminal 3

    WT_STORE_ENABLED=true WT_DOMAIN=remote ./wirething-poc.sh

## Testing using two computers

    # box01

    ln -nfs "<unpacked_path>/wireproxy" ./wireproxy
    export WIREPROXY_COMMAND="${PWD}/wireproxy"
    export WIREPROXY_EXPOSE_PORT_LIST="22"

    ./wirething-poc.sh cli new wire alice
    ./wirething-poc.sh cli export wire alice

    scp alice.peer box02:

    # box02

    ln -nfs "<unpacked_path>/wireproxy" ./wireproxy
    export WIREPROXY_COMMAND="${PWD}/wireproxy"
    export WIREPROXY_EXPOSE_PORT_LIST="22"

    ./wirething-poc.sh cli new wire bob
    ./wirething-poc.sh cli export wre bob

    scp bob.peer box01:

    # box01

    ./wirething-poc.sh cli add wire ~/bob.peer
    WT_STORE_ENABLED=true WT_DOMAIN=wire ./wirething-poc.sh

    # box02

    ./wirething-poc.sh cli add wire ~/alice.peer
    WT_STORE_ENABLED=true WT_DOMAIN=wire ./wirething-poc.sh

    # box01

    bob_address="$(./wirething-poc.sh cli peer address wire bob)"
    ssh -o ProxyCommand='nc -X 5 --proxy 127.0.0.1:1080 %h %p' "${USER}@${bob_address}"

    # box02

    alice_address="$(./wirething-poc.sh cli peer address wire alice)"
    ssh -o ProxyCommand='nc -X 5 --proxy 127.0.0.1:1080 %h %p' "${USER}@${alice_address}"
