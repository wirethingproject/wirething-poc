
# NixOS

## Install

    mkdir -p /etc/nixos/wirething-poc
    git clone https://github.com/wirethingproject/wirething-poc.git /etc/nixos/wirething-poc/src

## Domain Setup

Choose a _<domain>_ name and create a folder with chosen name in the path bellow:

    mkdir -p /etc/nixos/wirething-poc/<domain>

See the README.md for setup instrunctions not related with NixOS.

## systemd Setup

In the bellow configuration, replace _<domain>_ with the chosen name.

    { config, pkgs, ... }:

    let
      wirethingUnit = {
        serviceConfig = {
          Type = "simple";
          Restart = "on-failure";
          RestartSec = "30s";
          ExecStart = "/etc/nixos/wirething-poc/src/wirething-poc.sh";
          WorkingDirectory = "/etc/nixos/wirething-poc/%i";
          EnvironmentFile = "/etc/nixos/wirething-poc/%i/env";
          SyslogIdentifier = "wirething-poc";
        };
      };
      wirethingService = {
        enable = true;
        path = with pkgs; [ bash util-linux lsof curl gnupg openssl python3Minimal iputils procps stuntman wireguard-go wireguard-tools ];
        after=[ "network-online.target" "nss-lookup.target" ];
        wants=[ "network-online.target" "nss-lookup.target" ];
        wantedBy = [ "multi-user.target" ];
        overrideStrategy = "asDropin";
      };
    in
    {
      environment.systemPackages = with pkgs; [
        bash-interactive
        coreutils-full
        curl
        findutils
        git
        gnugrep
        gnupg
        gnused
        lsof
        openssl
        python3Minimal
        stuntman
        util-linux
        wireguard-go
        wireguard-tools
      ];

      systemd.services."wirething-poc@" = wirethingUnit;
      systemd.services."wirething-poc@<domain>" = wirethingService;
    }
