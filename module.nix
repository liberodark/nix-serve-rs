{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.nix-serve-rs;

  formatValue =
    v:
    if lib.isBool v then
      if v then "true" else "false"
    else if lib.isList v then
      "[ " + lib.concatMapStringsSep ", " (x: ''"${toString x}"'') v + " ]"
    else if lib.isString v then
      ''"${v}"''
    else
      toString v;

  baseSettings = {
    bind = "${cfg.bindAddress}:${toString cfg.port}";
    workers = cfg.workers;
    max_connections = cfg.maxConnections;
    priority = cfg.priority;
    virtual_store = cfg.virtualStore;
    compress_nars = cfg.compressNars;
    compression_level = cfg.compressionLevel;
    compression_format = cfg.compressionFormat;
    require_auth_uploads = cfg.requireAuthUploads;
  };

  effectiveSettings =
    baseSettings
    // lib.optionalAttrs (cfg.realStore != null) { real_store = cfg.realStore; }
    // lib.optionalAttrs (cfg.signKeyPath != null || cfg.signKeyPaths != []) {
      sign_key_paths = if cfg.signKeyPath != null
                       then [ cfg.signKeyPath ] ++ cfg.signKeyPaths
                       else cfg.signKeyPaths;
    }
    // lib.optionalAttrs (cfg.tlsCertPath != null) { tls_cert_path = cfg.tlsCertPath; }
    // lib.optionalAttrs (cfg.tlsKeyPath != null) { tls_key_path = cfg.tlsKeyPath; };

  configContent = lib.concatStringsSep "\n" (
    lib.mapAttrsToList (k: v: "${k} = ${formatValue v}") effectiveSettings
  );

  configFile = pkgs.writeText "nix-serve-rs.toml" configContent;

in
{
  options.services.nix-serve-rs = {
    enable = lib.mkEnableOption "nix-serve-rs binary cache server";

    package = lib.mkPackageOption pkgs "nix-serve-rs" { };

    bind = lib.mkOption {
      type = lib.types.str;
      default = "${cfg.bindAddress}:${toString cfg.port}";
      description = lib.mdDoc "Address and port to bind to (overrides bindAddress and port if set)";
    };

    bindAddress = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = lib.mdDoc "Address to bind to";
    };

    port = lib.mkOption {
      type = lib.types.int;
      default = 5000;
      description = lib.mdDoc "Port to bind to";
    };

    workers = lib.mkOption {
      type = lib.types.int;
      default = 4;
      description = lib.mdDoc "Number of worker threads (recommended: number of CPU cores)";
    };

    maxConnections = lib.mkOption {
      type = lib.types.int;
      default = 1024;
      description = lib.mdDoc "Maximum number of concurrent connections";
    };

    priority = lib.mkOption {
      type = lib.types.int;
      default = 30;
      description = lib.mdDoc "Binary cache priority (lower is higher priority)";
    };

    virtualStore = lib.mkOption {
      type = lib.types.str;
      default = "/nix/store";
      description = lib.mdDoc "Virtual Nix store path (as advertised to clients)";
    };

    realStore = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = lib.mdDoc "Physical Nix store path (where files are actually located)";
    };

    signKeyPath = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = lib.mdDoc "Path to the binary cache signing key (deprecated, use signKeyPaths instead)";
    };

    signKeyPaths = lib.mkOption {
      type = lib.types.listOf lib.types.path;
      default = [];
      description = lib.mdDoc "List of paths to binary cache signing keys";
    };

    compressNars = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = lib.mdDoc "Whether to compress NARs when serving them";
    };

    compressionLevel = lib.mkOption {
      type = lib.types.int;
      default = 3;
      description = lib.mdDoc "Compression level (1-19 for zstd, 0-9 for xz)";
    };

    compressionFormat = lib.mkOption {
      type = lib.types.enum [ "xz" "zstd" ];
      default = "xz";
      description = lib.mdDoc "Compression format to use (xz or zstd)";
    };

    requireAuthUploads = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = lib.mdDoc "Whether to require authentication for uploads";
    };

    tlsCertPath = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = lib.mdDoc "Path to TLS certificate file";
    };

    tlsKeyPath = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = lib.mdDoc "Path to TLS key file";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "nix-serve";
      description = lib.mdDoc "User to run nix-serve-rs as";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "nix-serve";
      description = lib.mdDoc "Group to run nix-serve-rs as";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.workers > 0;
        message = "services.nix-serve-rs.workers must be greater than 0";
      }
      {
        assertion = cfg.compressionLevel >= 1 && cfg.compressionLevel <= 19;
        message = "services.nix-serve-rs.compressionLevel must be between 1 and 19";
      }
      {
        assertion = (cfg.tlsCertPath == null) == (cfg.tlsKeyPath == null);
        message = "services.nix-serve-rs: tlsCertPath and tlsKeyPath must be either both set or both unset";
      }
    ];

    users.users.${cfg.user} = lib.mkIf (cfg.user == "nix-serve") {
      isSystemUser = true;
      group = cfg.group;
      description = "nix-serve-rs user";
    };

    users.groups.${cfg.group} = lib.mkIf (cfg.group == "nix-serve") { };

    nix.settings.allowed-users = [ cfg.user ];

    systemd.tmpfiles.settings."10-nix-serve-rs" =
      lib.optionalAttrs (cfg.signKeyPath != null) {
        ${builtins.dirOf (toString cfg.signKeyPath)} = {
          d = {
            mode = "0750";
            user = cfg.user;
            group = cfg.group;
          };
        };
      }
      // lib.foldl' (acc: path:
          acc // {
            ${builtins.dirOf (toString path)} = {
              d = {
                mode = "0750";
                user = cfg.user;
                group = cfg.group;
              };
            };
          }
        ) {} cfg.signKeyPaths
      // lib.optionalAttrs (cfg.realStore != null) {
        ${cfg.realStore} = {
          d = {
            mode = "0750";
            user = cfg.user;
            group = cfg.group;
          };
        };
        "${cfg.realStore}/nar" = {
          d = {
            mode = "0750";
            user = cfg.user;
            group = cfg.group;
          };
        };
      }
      // lib.optionalAttrs (cfg.tlsCertPath != null) {
        ${builtins.dirOf (toString cfg.tlsCertPath)} = {
          d = {
            mode = "0750";
            user = cfg.user;
            group = cfg.group;
          };
        };
      }
      // lib.optionalAttrs (cfg.tlsKeyPath != null) {
        ${builtins.dirOf (toString cfg.tlsKeyPath)} = {
          d = {
            mode = "0750";
            user = cfg.user;
            group = cfg.group;
          };
        };
      };

    systemd.services.nix-serve-rs = {
      description = "nix-serve-rs binary cache server";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      startLimitIntervalSec = 180;
      startLimitBurst = 5;

      environment = {
        NIX_SERVE_CONFIG = configFile;
      };

      serviceConfig = {
        Type = "simple";
        ExecStart = "${lib.getExe cfg.package} --config ${configFile}";
        Restart = "on-failure";
        RestartSec = "2";
      };
    };
  };
}
