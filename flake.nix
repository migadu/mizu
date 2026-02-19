{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = nixpkgs.legacyPackages.${system};
      in {
        devShells.default = pkgs.mkShell {
          name = "mizu-env";
          buildInputs = [
            # goEnv
            # gomod2nix
            pkgs.golangci-lint
            pkgs.go
            pkgs.gotools
            pkgs.go-junit-report
            pkgs.go-task
          ];
          env = {
            lang = "en_us.utf-8";

          };
          shellhook = "\n";

        };
      });
}
