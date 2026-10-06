# Update implementation status

Automatic updates are under development. The application currently supplies
no update worker, so Settings disables manual checks and reports that updates
are unavailable. Update preferences are persisted for the future integration.

The shared core validates signed manifests, selects candidates, schedules
checks, and reduces platform events. The UI exposes download and completion
actions. Restart completion goes through active-session confirmation and
shutdown; opening a downloaded artifact or a system installer does not close
sessions.

Linux provides installation detection, verified AppImage staging, private
state files, and desktop package handoff primitives. Windows provides pinned
Velopack packaging and lifecycle hooks. macOS provides a Sparkle bridge and
signed appcast packaging. These platform pieces are not yet connected to the
shared worker in the application.

Before enabling automatic updates, connect concrete backends, provision the
trusted manifest public key, publish `conman-update.json` and its signature
after the referenced packages, and verify native installation and restart
behavior on every supported platform. macOS Sparkle keys are separate from
the shared manifest-signing key.
