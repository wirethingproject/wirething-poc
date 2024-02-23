# wirething-poc

This proof of concept uses the [ntfy](https://ntfy.sh) service, the project
[udphole](https://github.com/wirethingproject/udphole) deployed to
[fly.io](https://fly.io) and [wireguard](https://www.wireguard.com) to connect
without any login two devices behind NAT.

    # macOS

    brew install bash gnupg wireguard-tools wireguard-go

    # Setup
    bash
    umask 077

    mkdir "mesh"
    cd "mesh"

    mkdir "gpg"
    export GNUPGHOME="${PWD}/gpg"


    name="alice"

    wg genkey > "${name}.key"
    cat "${name}.key" | wg pubkey > "${name}.pub"

    key_name="$(cat "${name}.pub")@wirething.gpg"
    gpg --pinentry-mode=loopback  --passphrase "" --yes --quick-generate-key "${key_name}"
    gpg --armor --export-secret-keys "${key_name}" > "${name}-key.gpg"
    gpg --armor --export "${key_name}" > "${name}-pub.gpg"


    name="bob"

    wg genkey > "${name}.key"
    cat "${name}.key" | wg pubkey > "${name}.pub"

    key_name="$(cat "${name}.pub")@wirething.gpg"
    gpg --pinentry-mode=loopback  --passphrase "" --yes --quick-generate-key "${key_name}"
    gpg --armor --export-secret-keys "${key_name}" > "${name}-key.gpg"
    gpg --armor --export "${key_name}" > "${name}-pub.gpg"


    unset GNUPGHOME
    rm -rvf "gpg"

    # Terminal 1
    sudo WGQ_HOST_PRIVATE_KEY_FILE=alice.key WGQ_PEER_PUBLIC_KEY_FILE_LIST=bob.pub \
        GPG_FILE_LIST="alice-key.gpg bob-pub.gpg" \
        ../wirething-poc.sh

    # Terminal 2
    sudo WGQ_HOST_PRIVATE_KEY_FILE=bob.key WGQ_PEER_PUBLIC_KEY_FILE_LIST=alice.pub \
        GPG_FILE_LIST="bob-key.gpg alice-pub.gpg" \
        ../wirething-poc.sh

    # Terminal 3
    sudo wg show
