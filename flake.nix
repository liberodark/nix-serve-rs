{
  description = "High-performance Nix binary cache server implemented in pure Rust";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rust-src"
            "rust-analyzer"
            "clippy"
            "rustfmt"
          ];
        };

        buildInputs = with pkgs; [
          openssl.dev
          pkg-config
        ];

        devInputs = with pkgs; [
          rustToolchain
          rust-analyzer
          clippy
          rustfmt
          cargo-watch
          cargo-audit
          cargo-edit
          nixpkgs-fmt
        ];
      in
      {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "nix-serve-rs";
          version = "0.1.0";
          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          buildInputs = buildInputs;
          nativeBuildInputs = [ pkgs.pkg-config ];

          doCheck = true;

          meta = {
            description = "High-performance Nix binary cache server implemented in pure Rust";
            homepage = "https://github.com/liberodark/nix-serve-rs";
            license = lib.licenses.gpl3Only;
            maintainers = with lib.maintainers; [ liberodark ];
          };
        };

        nixosModules.default =
          {
            config,
            lib,
            pkgs,
            ...
          }:
          with lib;
          let
            cfg = config.services.nix-serve-rs;
          in
          {
            options.services.nix-serve-rs = {
              enable = mkEnableOption "nix-serve-rs binary cache server";

              package = mkOption {
                type = types.package;
                default = self.packages.${system}.default;
                description = "nix-serve-rs package to use";
              };

              bind = mkOption {
                type = types.str;
                default = "[::]:5000";
                description = "Address and port to bind to";
              };

              workers = mkOption {
                type = types.int;
                default = 4;
                description = "Number of worker threads";
              };

              virtualStore = mkOption {
                type = types.str;
                default = "/nix/store";
                description = "Virtual Nix store path (as advertised to clients)";
              };

              realStore = mkOption {
                type = types.nullOr types.str;
                default = null;
                description = "Physical Nix store path (where files are actually located)";
              };

              signKeyPath = mkOption {
                type = types.nullOr types.path;
                default = null;
                description = "Path to the binary cache signing key";
              };

              user = mkOption {
                type = types.str;
                default = "nix-serve";
                description = "User to run nix-serve-rs as";
              };

              group = mkOption {
                type = types.str;
                default = "nix-serve";
                description = "Group to run nix-serve-rs as";
              };
            };

            config = mkIf cfg.enable {
              users.users.${cfg.user} = {
                isSystemUser = true;
                group = cfg.group;
                description = "nix-serve-rs user";
              };

              users.groups.${cfg.group} = { };

              nix.settings.allowed-users = [ cfg.user ];

              environment.etc."nix-serve-rs/config.toml".text = ''
                bind = "${cfg.bind}"
                workers = ${toString cfg.workers}
                priority = 30
                virtual_store = "${cfg.virtualStore}"
                ${optionalString (cfg.realStore != null) ''real_store = "${cfg.realStore}"''}
                ${optionalString (cfg.signKeyPath != null) ''sign_key_paths = ["${cfg.signKeyPath}"]''}
              '';

              systemd.services.nix-serve-rs = {
                description = "nix-serve-rs binary cache server";
                wantedBy = [ "multi-user.target" ];
                after = [ "network.target" ];

                environment = {
                  NIX_SERVE_CONFIG = "/etc/nix-serve-rs/config.toml";
                };

                serviceConfig = {
                  ExecStart = "${cfg.package}/bin/nix-serve-rs";
                  User = cfg.user;
                  Group = cfg.group;
                  Restart = "always";

                  ProtectSystem = "strict";
                  ProtectHome = true;
                  PrivateTmp = true;
                  PrivateDevices = true;
                  NoNewPrivileges = true;

                  LimitNOFILE = 65536;
                };
              };
            };
          };

        devShells.default = pkgs.mkShell {
          buildInputs = buildInputs ++ devInputs;

          RUST_BACKTRACE = 1;
        };
      }
    );
}
