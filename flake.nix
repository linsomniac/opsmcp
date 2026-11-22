{
  description = "opsmcp: an MCP server giving AI agents audited, permission-controlled access to Linux operations tasks";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      # opsmcp is for Linux hosts only.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: rec {
        opsmcp = pkgs.callPackage ./nix/package.nix { };
        # Statically linked, for copying to hosts of any distribution.
        opsmcp-static = pkgs.pkgsStatic.callPackage ./nix/package.nix { };
        default = opsmcp;
      });

      overlays.default = final: _prev: {
        opsmcp = final.callPackage ./nix/package.nix { };
      };

      nixosModules.default = import ./nix/module.nix { inherit self; };

      checks = forAllSystems (pkgs: {
        opsmcp = self.packages.${pkgs.stdenv.hostPlatform.system}.opsmcp;
        nixos-module = import ./nix/test.nix {
          inherit pkgs;
          module = self.nixosModules.default;
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            clippy
            rust-analyzer
            rustc
            rustfmt
          ];
          RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
