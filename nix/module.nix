# NixOS module for a host that agents reach through opsmcp:
#
#   services.opsmcp = {
#     enable = true;
#     sudoGroups = [ "wheel" ];
#     settings = {
#       roles.readonly.allow = [ "@read" ];
#       unix_groups.wheel.roles = [ "readonly" ];
#     };
#   };
#
# It installs the package, writes /etc/opsmcp/config.toml from `settings`, and can add
# the sudo rule and the HTTPS service. Like the .deb, it gives nobody access by itself:
# without roles in `settings` every caller is turned away.
{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.opsmcp;
  toml = pkgs.formats.toml { };
  # AIDEV-NOTE: sudo rules and fleet servers name opsmcp by path, so it is always
  # started through the system profile, never through a store path that changes with
  # every update.
  inProfile = "/run/current-system/sw/bin/opsmcp";
in
{
  options.services.opsmcp = {
    enable = lib.mkEnableOption "opsmcp, an MCP server for audited operations tasks on this host";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "opsmcp.packages.\${pkgs.stdenv.hostPlatform.system}.default";
      description = "The opsmcp package to use.";
    };

    settings = lib.mkOption {
      type = toml.type;
      default = { };
      example = lib.literalExpression ''
        {
          roles.readonly.allow = [ "@read" ];
          unix_groups.wheel.roles = [ "readonly" ];
        }
      '';
      description = ''
        The contents of {file}`/etc/opsmcp/config.toml`: the roles, who holds them, and
        everything else opsmcp is configured with. The package's
        {file}`share/opsmcp/examples/config.example.toml` describes every setting.

        The file is kept in the Nix store, which everyone on the host can read. That is
        fine for what belongs in it: tokens are given as their SHA-256 hashes, never as
        the tokens themselves.
      '';
    };

    sudoGroups = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "wheel" ];
      description = ''
        Groups whose members may start `opsmcp serve` as root with sudo, without a
        password. That is how a local agent, or one that connects over SSH, reaches
        opsmcp. Being able to start it grants nothing by itself: what a member may do is
        decided by the roles they hold in {option}`services.opsmcp.settings`.
      '';
    };

    usrBinLink = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Whether to link {file}`/usr/bin/opsmcp` to the package. A fleet server runs
        `sudo -n /usr/bin/opsmcp serve` on its hosts, which is where other distributions
        have the binary; with this link a NixOS host answers to the same command.
      '';
    };

    http.enable = lib.mkEnableOption ''
      the HTTPS server (`opsmcp serve-http`). It listens as configured under
      `settings.http`, which then has to name `listen`, `tls_cert` and `tls_key`
    '';
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.http.enable -> cfg.settings ? http;
        message = "services.opsmcp.http.enable needs services.opsmcp.settings.http (listen, tls_cert and tls_key).";
      }
    ];

    environment.systemPackages = [ cfg.package ];
    environment.etc."opsmcp/config.toml".source = toml.generate "opsmcp-config.toml" cfg.settings;

    # sudo matches the command and its arguments exactly, so this allows `opsmcp serve`
    # with the configuration above and nothing else.
    security.sudo.extraRules = lib.mkIf (cfg.sudoGroups != [ ]) [
      {
        groups = cfg.sudoGroups;
        commands = map (path: {
          command = "${path} serve";
          options = [ "NOPASSWD" ];
        }) ([ inProfile ] ++ lib.optional cfg.usrBinLink "/usr/bin/opsmcp");
      }
    ];

    systemd.tmpfiles.rules = lib.mkIf cfg.usrBinLink [
      "L+ /usr/bin/opsmcp - - - - ${inProfile}"
    ];

    # The same service as packaging/opsmcp-http.service; see there for why it runs as
    # root and which hardening is deliberately left out.
    systemd.services.opsmcp-http = lib.mkIf cfg.http.enable {
      description = "opsmcp operations MCP server (HTTPS)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      restartTriggers = [ config.environment.etc."opsmcp/config.toml".source ];
      serviceConfig = {
        ExecStartPre = "${lib.getExe cfg.package} check-config";
        ExecStart = "${lib.getExe cfg.package} serve-http";
        Restart = "on-failure";
        RestartSec = 5;
        LimitNOFILE = 4096;
        TasksMax = 512;
        LockPersonality = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        ProtectHostname = true;
      };
    };
  };
}
