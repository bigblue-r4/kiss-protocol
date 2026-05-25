{
  description = "SGAIL Labs Harborlight Firewall — hermetic build";

  inputs = {
    nixpkgs.url     = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        witness = pkgs.buildGoModule {
          pname   = "witness";
          version = "2.0.0";
          src     = ./.;

          vendorHash = null; # set to pkgs.lib.fakeHash on first build, then fill in

          ldflags = [ "-s" "-w" "-trimpath" ];

          meta = with pkgs.lib; {
            description = "Tamper-evident machine-state logging for AI agent environments";
            homepage    = "https://github.com/bigblue-r4/kiss-protocol";
            license     = licenses.mit;
            maintainers = [];
            platforms   = platforms.linux ++ platforms.darwin;
          };
        };

      in {
        packages = {
          inherit witness;
          default = witness;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
            gopls
            gotools
            golangci-lint
            cosign
          ];
        };
      }
    );
}
