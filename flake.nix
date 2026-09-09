{
  description = "Carbonado Node storage provider";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # Binary Rust toolchains. Pin 1.98.0; nixpkgs-unstable rustc lagged this release.
    # https://blog.rust-lang.org/2026/08/20/Rust-1.98.0/ (accessed: 2026-08-24).
    # https://github.com/oxalica/rust-overlay (accessed: 2026-08-24).
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      crane,
    }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "aarch64-linux"
        "x86_64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      forAllSystems = lib.genAttrs systems;

      perSystem = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };

          rustToolchain = pkgs.rust-bin.stable."1.98.0".minimal.override {
            extensions = [
              "rust-src"
              "rustfmt"
              "clippy"
            ];
          };

          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

          src = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./rust-toolchain.toml
              ./src
              ./tests
            ];
          };

          commonArgs = {
            inherit src;
            pname = "carbonado-node";
            version = (craneLib.crateNameFromCargoToml { cargoToml = ./Cargo.toml; }).version;
            strictDeps = true;
            # Carbonado 0.7.0 and bao-tree 0.16.1 are crates.io. No git FODs.
            cargoVendorDir = craneLib.vendorCargoDeps {
              inherit src;
            };
            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [
              pkgs.openssl
            ]
            ++ lib.optionals pkgs.stdenv.hostPlatform.isDarwin [
              pkgs.libiconv
            ];
            # zstd-sys probes nixpkgs libzstd when ZSTD_SYS_USE_PKG_CONFIG is set.
            preConfigure = ''
              unset ZSTD_SYS_USE_PKG_CONFIG
            '';
          };

          mkCargoQuality = remote:
            import ./nix/cargo-quality.nix {
              inherit lib craneLib src commonArgs testEnv remote;
            };
          cargoChecks = mkCargoQuality false;
          cargoQuality = mkCargoQuality true;

          cargoArtifacts = craneLib.buildDepsOnly (
            commonArgs
            // {
              # Tests and the binary live in this crate; deps-only should still
              # see the lockfile graph, not run the suite.
              doCheck = false;
            }
          );

          carbonado-node = craneLib.buildPackage (
            commonArgs
            // {
              inherit cargoArtifacts;
              doCheck = false;
              meta = {
                description = "Carbonado Node storage provider HTTP frontend";
                homepage = "https://github.com/bitmask-stack/carbonado-node";
                mainProgram = "carbonadod";
              };
            }
          );

          testEnv = {
            # Integration tests write config and volume dirs via `directories`.
            preCheck = ''
              export HOME="$TMPDIR/home"
              export DATA_CFG_DIR="$TMPDIR/carbonado-cfg"
              mkdir -p "$HOME" "$DATA_CFG_DIR"
            '';
          };
        in
        {
          inherit
            pkgs
            rustToolchain
            craneLib
            src
            commonArgs
            cargoArtifacts
            carbonado-node
            testEnv
            cargoChecks
            cargoQuality
            ;
          cargoVendorDir = commonArgs.cargoVendorDir;
        }
      );
    in
    {
      packages = forAllSystems (system: {
        default = perSystem.${system}.carbonado-node;
        carbonado-node = perSystem.${system}.carbonado-node;
        carbonadod = perSystem.${system}.carbonado-node;
        # Lockfile vendor for local cargo clippy. Not a crates.io skip of menhera-cooldown.
        cargo-vendor = perSystem.${system}.cargoVendorDir;
        # Named Crane packages. `just check` runs local cargo fmt/clippy,
        # then remote nextest-quality. Not used by GHA.
        fmt-quality = perSystem.${system}.cargoQuality.fmt;
        clippy-quality = perSystem.${system}.cargoQuality.clippy;
        nextest-quality = perSystem.${system}.cargoQuality.nextest;
      });

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${perSystem.${system}.carbonado-node}/bin/carbonadod";
        };
      });

      checks = forAllSystems (
        system:
        let
          inherit (perSystem.${system}) carbonado-node cargoChecks;
        in
        {
          inherit carbonado-node;
          # GHA / just check-local. These do not require surmount-remote.
          fmt = cargoChecks.fmt;
          clippy = cargoChecks.clippy;
          nextest = cargoChecks.nextest;
        }
      );

      devShells = forAllSystems (
        system:
        let
          inherit (perSystem.${system}) pkgs craneLib rustToolchain;
        in
        {
          default = craneLib.devShell {
            packages = [
              rustToolchain
              pkgs.cargo-nextest
              pkgs.cargo-audit
              pkgs.pkg-config
              pkgs.openssl
            ];
          };
        }
      );
    };
}
