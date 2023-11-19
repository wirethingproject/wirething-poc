# wirething-poc

This proof of concept uses the [ntfy](https://ntfy.sh) service, the project
[udphole](https://github.com/wirethingproject/udphole) deployed to
[fly.io](https://fly.io) and [wireguard](https://www.wireguard.com) to connect
without any login two devices behind NAT.

    # Setup
    umask 077
    wg genkey > alice.key
    cat alice.key | wg pubkey > alice.pub
    wg genkey > bob.key
    cat bob.key | wg pubkey > bob.pub

    # Terminal 1
    sudo WG_HOST_PRIVATE_KEY_FILE=alice.key WG_PEER_PUBLIC_KEY_FILE_LIST=bob.pub ./wirething-poc.sh

    # Terminal 2
    sudo WG_HOST_PRIVATE_KEY_FILE=bob.key WG_PEER_PUBLIC_KEY_FILE_LIST=alice.pub ./wirething-poc.sh

    # Terminal 3
    sudo wg show
