
# NixOS

## systemd setup

      environment.systemPackages = with pkgs; [
        git
        gnupg
        lsof
        openssl
        python3Minimal
        wireguard-tools
      ];

      systemd.services = {
        "wirething-poc@".serviceConfig = {
          Type = "simple";
          Restart = "always";
          WorkingDirectory = "/home/<username>/%i";
          EnvironmentFile = "/home/<username>/%i/env";
          ExecStart = "/home/<username>/wirething-poc/wirething-poc.sh";
        };
        "wirething-poc@<hostname>" = {
          enable = true;
          path = with pkgs; [ bash util-linux lsof curl gnupg openssl python3Minimal iputils procps wireguard-tools ];
          wants=[ "network-online.target" "nss-lookup.target" ];
          after=[ "network-online.target" "nss-lookup.target" ];
          overrideStrategy = "asDropin";
          wantedBy = [ "multi-user.target" ];
        };
      };
