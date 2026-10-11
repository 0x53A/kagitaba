{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  packages = with pkgs; [ cargo rustc rustfmt clippy uv nodejs llvmPackages.lld git openssh coreutils ];
  LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath (with pkgs; [
    libGL libxkbcommon wayland libX11 libXcursor libXi libXrandr
  ]);
}
