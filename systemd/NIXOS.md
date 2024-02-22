
      environment.systemPackages = with pkgs; [
        gnupg
        lsof
        openssl
        python3Minimal
        wireguard-tools
      ];

      systemd.services.wirething-poc-<hostname> = {
        path = with pkgs; [ bash util-linux lsof curl gnupg openssl python3Minimal wireguard-tools ];
        wants=[ "network-online.target" "nss-lookup.target" ];
        after=[ "network-online.target" "nss-lookup.target" ];
        serviceConfig = {
          Type = "simple";
          Restart = "always";
          WorkingDirectory = "<config_path>/<hostname>";
          EnvironmentFile = "<config_path>/<hostname>/env";
          ExecStart = "<bin_path>/wirething-poc.sh";
        };
      };

