INSTALL CONMAN

1. Drag ConMan.app onto the Applications shortcut.
2. Open ConMan from Applications.

OPTIONAL COMMAND-LINE TOOL

After installing the app, double-click “Install conmanctl.command”. macOS will
ask for an administrator password and create this symlink:

    /usr/local/bin/conmanctl
      -> /Applications/ConMan.app/Contents/Helpers/conmanctl.app/Contents/MacOS/conmanctl

This keeps conmanctl on the same version as the app when ConMan.app is replaced.
To remove the symlink without removing the app, run:

    "/Volumes/ConMan <version>/Install conmanctl.command" --remove

The installer refuses to overwrite or remove an unrelated file at that path.
