# NixOS VM test: a host set up by the module answers a caller over sudo and over HTTPS,
# turns away everyone else, and records the calls.
{ pkgs, module }:
let
  # Not a secret: it only exists inside the test machine.
  token = "opsmcp_token_for_the_nixos_test";
  request = pkgs.writeText "system-info.json" (
    builtins.toJSON {
      jsonrpc = "2.0";
      id = 1;
      method = "tools/call";
      params = {
        name = "system_info";
        arguments = { };
      };
    }
  );
  tls = "/var/lib/opsmcp-test";
in
pkgs.testers.runNixOSTest {
  name = "opsmcp";

  nodes.machine = {
    imports = [ module ];

    services.opsmcp = {
      enable = true;
      sudoGroups = [ "ops" ];
      usrBinLink = true;
      http.enable = true;
      settings = {
        roles.readonly.allow = [ "@read" ];
        unix_groups.ops.roles = [ "readonly" ];
        tokens.ci = {
          sha256 = builtins.hashString "sha256" token;
          roles = [ "readonly" ];
        };
        http = {
          listen = "127.0.0.1:8443";
          tls_cert = "${tls}/server.crt";
          tls_key = "${tls}/server.key";
        };
      };
    };

    users.groups.ops = { };
    users.users.alice = {
      isNormalUser = true;
      extraGroups = [ "ops" ];
    };
    users.users.bob.isNormalUser = true;
    environment.systemPackages = [ pkgs.curl ];

    # The server's certificate, made before the server starts.
    systemd.services.opsmcp-test-certificate = {
      wantedBy = [ "opsmcp-http.service" ];
      before = [ "opsmcp-http.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      path = [ pkgs.openssl ];
      script = ''
        umask 077
        mkdir -p ${tls}
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
          -subj /CN=localhost -addext subjectAltName=DNS:localhost \
          -keyout ${tls}/server.key -out ${tls}/server.crt
        chmod 0755 ${tls}
        chmod 0644 ${tls}/server.crt
      '';
    };
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")

    with subtest("the configuration the module wrote is one opsmcp accepts"):
        machine.succeed("opsmcp check-config")

    with subtest("a member of the sudo group is answered"):
        for opsmcp in ["opsmcp", "/usr/bin/opsmcp"]:
            answer = machine.succeed(f"su - alice -c 'sudo -n {opsmcp} serve < ${request}'")
            assert "Kernel:" in answer, answer

    with subtest("nobody else can start it as root"):
        machine.fail("su - bob -c 'sudo -n opsmcp serve < ${request}'")

    with subtest("the HTTPS server answers a caller with a token, and nobody without one"):
        machine.wait_for_unit("opsmcp-http.service")
        machine.wait_for_open_port(8443)
        call = (
            "curl -sS --cacert ${tls}/server.crt -H 'Content-Type: application/json'"
            " -d @${request} https://localhost:8443/mcp"
        )
        answer = machine.succeed(call + " -H 'Authorization: Bearer ${token}'")
        assert "Kernel:" in answer, answer
        status = machine.succeed(call + " -o /dev/null -w '%{http_code}'")
        assert status == "401", status

    with subtest("the calls are in the audit trail"):
        trail = machine.succeed("journalctl --no-pager -o cat | grep -F '\"tool\":\"system_info\"'")
        assert '"principal":"alice"' in trail, trail
        assert '"principal":"token:ci"' in trail, trail
  '';
}
