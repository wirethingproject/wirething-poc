
# disabled encryption

function disabled_encryption() {
    action="${1}" && shift
    case "${action}" in
        deps)
            echo "base64"
            ;;
        encrypt)
            id="${1}" && shift
            data="${1}" && shift
            echo "${data}" | base64
            ;;
        decrypt)
            id="${1}" && shift
            data="${1}" && shift
            echo "${data}" | base64 -d
            ;;
    esac
}
