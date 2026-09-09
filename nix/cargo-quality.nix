# Crane fmt / clippy / nextest for carbonado-node.
#
# `just check` runs cargo fmt and cargo clippy on this machine, then
# remote `nextest-quality` (`remote = true`, surmount-remote). `remote =
# false` stays for flake checks. This crate has no wasm32 target.
{
  lib,
  craneLib,
  src,
  commonArgs,
  testEnv,
  remote ? false,
}: let
  remoteSystemFeatures = [
    "big-parallel"
    "surmount-remote"
  ];

  remoteAttrs = lib.optionalAttrs remote {
    preferLocalBuild = false;
    requiredSystemFeatures = remoteSystemFeatures;
  };

  pnameSuffix =
    if remote
    then "-quality"
    else "";

  applyRemote = drv: drv.overrideAttrs (_: remoteAttrs);

  qualityArgs =
    commonArgs
    // remoteAttrs
    // {
      enableParallelBuilding = true;
      CARGO_BUILD_JOBS = "32";
      CARGO_PROFILE = "dev";
    };

  cargoArtifacts = craneLib.buildDepsOnly (qualityArgs
    // {
      pname = "carbonado-node-deps${pnameSuffix}";
      cargoExtraArgs = "--locked";
      doCheck = false;
    });

  fmt = applyRemote (craneLib.cargoFmt {
    inherit src;
    pname = "carbonado-node-fmt${pnameSuffix}";
    cargoExtraArgs = "--all";
  });

  clippy = applyRemote (craneLib.cargoClippy (qualityArgs
    // {
      inherit cargoArtifacts;
      pname = "carbonado-node-clippy${pnameSuffix}";
      cargoExtraArgs = "--locked";
      cargoClippyExtraArgs = "--all-targets --all-features -- --deny warnings";
      doInstallCargoArtifacts = false;
    }));

  nextest = applyRemote (craneLib.cargoNextest (qualityArgs
    // testEnv
    // {
      inherit cargoArtifacts;
      pname = "carbonado-node-nextest${pnameSuffix}";
      partitions = 1;
      partitionType = "count";
      cargoNextestExtraArgs = "--no-fail-fast";
    }));
in {
  inherit fmt clippy nextest;
}
