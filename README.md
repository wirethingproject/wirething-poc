# wirething-poc

    # Setup

    umask 077

    wg genkey > alice.key
    cat alice.key | wg pubkey > alice.pub

    wg genkey > bob.key
    cat bob.key | wg pubkey > bob.pub

    # Terminal 1
    sudo WG_HOST_PRIVATE_KEY_FILE=alice.key WG_PEER_PUBLIC_KEY_FILE_LIST=bob.pub ../../wirething-poc/wirething-poc.sh

    # Terminal 2
    sudo WG_HOST_PRIVATE_KEY_FILE=bob.key WG_PEER_PUBLIC_KEY_FILE_LIST=alice.pub ../../wirething-poc/wirething-poc.sh

    # Terminal 3
    sudo wg show
