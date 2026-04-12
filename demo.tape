Output demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1280
Set Height 780
Set Theme "Catppuccin Mocha"
Set TypingSpeed 25ms
Set Framerate 18
Set Padding 10

# Isolate netscan's config/data to a throwaway HOME so the demo is
# deterministic and doesn't touch the user's real history.
Hide
Type "bash -lc 'export HOME=/tmp/netscan-demo-home && rm -rf $HOME && mkdir -p $HOME && /Users/matt/projects/netscan/target/release/netscan'"
Enter
Sleep 2500ms
Show

# Landing on the Targets tab with two default groups (localhost, home-lan).
# The first one (localhost) is selected.
Sleep 1500ms

# Start the first scan — shows the live progress bar + streaming hosts.
Enter
Sleep 4s

# Rerun the same scan to show the auto-diff pane appearing below the host list.
Enter
Sleep 4s

# Cycle the theme three times so viewers see the palette options.
Type "t"
Sleep 800ms
Type "t"
Sleep 800ms
Type "t"
Sleep 800ms
Type "t"
Sleep 800ms
Type "t"
Sleep 800ms

# Switch to the History tab to show the persisted scan list.
Type "4"
Sleep 2500ms

# Quit cleanly.
Type "q"
Sleep 500ms
