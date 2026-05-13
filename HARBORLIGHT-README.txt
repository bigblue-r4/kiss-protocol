SGAIL Labs Harborlight Firewall
USB Installer
================================

No internet needed. No technical knowledge needed.
Just follow the steps for your computer type below.


── MAC ──────────────────────────────────────────────

1. Plug in the USB stick.

2. Open the USB folder in Finder.

3. Double-click the file called:  install.command

4. If Mac says it can't open it:
   → Right-click (or Control-click) on install.command
   → Choose "Open"
   → Click "Open" in the dialog that appears

5. A Terminal window will open.
   Answer the one question it asks (just press Enter to accept the default).

6. Done. Close the Terminal window when it says "Installation complete."


── LINUX ────────────────────────────────────────────

1. Plug in the USB stick.

2. Open a Terminal.

3. Type this and press Enter:
   bash /path/to/usb/install.sh

   (Replace /path/to/usb with wherever your USB mounted,
    usually something like /media/yourname/HARBORLIGHT)

4. Answer the one question it asks (just press Enter to accept the default).

5. Done.


── AFTER INSTALL ────────────────────────────────────

Open a new Terminal window and type:

   witness --version
   pipelock --version

Both should print their version numbers. If you see
"command not found", close and reopen your Terminal and try again.


── SOMETHING WRONG? ─────────────────────────────────

The installer saves a log file to:  /tmp/sgail-harborlight-install-[date].log

Send that file to whoever gave you this USB stick.


── WHAT GETS INSTALLED ──────────────────────────────

  witness    → ~/.local/bin/witness
               config at ~/.witness/

  pipelock   → ~/.local/bin/pipelock
               config at ~/.pipelock/

Nothing else. No background services are started automatically.
Your existing configs are never overwritten.
