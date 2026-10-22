{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  packages = with pkgs; [ cargo rustc rustfmt clippy uv nodejs llvmPackages.lld git openssh coreutils ffmpeg ];
  NIX_LDFLAGS = "-rpath ${pkgs.lib.getLib pkgs.dbus}/lib";
  LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath (with pkgs; [
    dbus libGL libxkbcommon wayland libX11 libXcursor libXi libXrandr
  ]);
}
