# sinsp-debug

This simple executable can be used to debug sinsp through scap-files.
Right now it prints relevant info about processes but in the next future it could be enriched:

# Build and run it 🏎️

From the build directory:

```bash
cmake -DBUILD_DRIVER=On -DUSE_BUNDLED_DEPS=Off -DMINIMAL_BUILD=On ..
make sinsp-debug
# It takes just one arg, the path to the scap-file (relative or absolute)
sudo ./libsinsp/sinsp_debug/sinsp-debug <path_to_scap_file>
```

# Example output

```
🧵 CLONE CALLER EXIT: 2704891
📜 Task Lineage for tid: 48694
⬇️ [apt-check] t: 48694, p: 48694, rpt: 5022, vt: 48694, vp: 48694, vs: 1921, vpg: 1921, ct: 0, e: /usr/lib/update-notifier/apt-check
⬇️ [update-notifier] t: 5022, p: 5022, rpt: 1921, vt: 5022, vp: 5022, vs: 1921, vpg: 1921, ct: 0, e: /usr/bin/update-notifier
⬇️ [gnome-session-b] t: 1921, p: 1921, rpt: 1406, vt: 1921, vp: 1921, vs: 1921, vpg: 1921, ct: 0, e: /usr/libexec/gnome-session-binary
⬇️ [systemd] t: 1406, p: 1406, rpt: 1, vt: 1406, vp: 1406, vs: 1406, vpg: 1406, ct: 0, e: /usr/lib/systemd/systemd
⬇️ [systemd]💀 t: 1, p: 1, rpt: 0, vt: 1, vp: 1, vs: 1, vpg: 1, ct: 0, e: /usr/lib/systemd/systemd
END

🟢 EXECVE EXIT: 2704902
📜 Task Lineage for tid: 48812
⬇️ [lsb_release] t: 48812, p: 48812, rpt: 48694, vt: 48812, vp: 48812, vs: 1921, vpg: 1921, ct: 0, e: /usr/bin/lsb_release
⬇️ [apt-check] t: 48694, p: 48694, rpt: 5022, vt: 48694, vp: 48694, vs: 1921, vpg: 1921, ct: 0, e: /usr/lib/update-notifier/apt-check
⬇️ [update-notifier] t: 5022, p: 5022, rpt: 1921, vt: 5022, vp: 5022, vs: 1921, vpg: 1921, ct: 0, e: /usr/bin/update-notifier
⬇️ [gnome-session-b] t: 1921, p: 1921, rpt: 1406, vt: 1921, vp: 1921, vs: 1921, vpg: 1921, ct: 0, e: /usr/libexec/gnome-session-binary
⬇️ [systemd] t: 1406, p: 1406, rpt: 1, vt: 1406, vp: 1406, vs: 1406, vpg: 1406, ct: 0, e: /usr/lib/systemd/systemd
⬇️ [systemd]💀 t: 1, p: 1, rpt: 0, vt: 1, vp: 1, vs: 1, vpg: 1, ct: 0, e: /usr/lib/systemd/systemd
END

💥 THREAD EXIT: 2712161
📜 Task Lineage for tid: 48812
⬇️ [lsb_release] t: 48812, p: 48812, rpt: 48694, vt: 48812, vp: 48812, vs: 1921, vpg: 1921, ct: 0, e: /usr/bin/lsb_release
⬇️ [apt-check] t: 48694, p: 48694, rpt: 5022, vt: 48694, vp: 48694, vs: 1921, vpg: 1921, ct: 0, e: /usr/lib/update-notifier/apt-check
⬇️ [update-notifier] t: 5022, p: 5022, rpt: 1921, vt: 5022, vp: 5022, vs: 1921, vpg: 1921, ct: 0, e: /usr/bin/update-notifier
⬇️ [gnome-session-b] t: 1921, p: 1921, rpt: 1406, vt: 1921, vp: 1921, vs: 1921, vpg: 1921, ct: 0, e: /usr/libexec/gnome-session-binary
⬇️ [systemd] t: 1406, p: 1406, rpt: 1, vt: 1406, vp: 1406, vs: 1406, vpg: 1406, ct: 0, e: /usr/lib/systemd/systemd
⬇️ [systemd]💀 t: 1, p: 1, rpt: 0, vt: 1, vp: 1, vs: 1, vpg: 1, ct: 0, e: /usr/lib/systemd/systemd
END
```
