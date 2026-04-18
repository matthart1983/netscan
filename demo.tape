Output demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1280
Set Height 780
Set Theme "Catppuccin Mocha"
Set TypingSpeed 25ms
Set Framerate 18
Set Padding 10

# Seed a throwaway HOME with a sample scan so History and Topology have data
# without needing a live network. demo-seed.sh creates targets.toml and
# populates history.db with a 5-host demo-lan scan.
Hide
Type `bash -lc 'HOME_DEMO=/tmp/netscan-demo-home /Users/matt/projects/netscan/demo-seed.sh && HOME=/tmp/netscan-demo-home /Users/matt/projects/netscan/target/release/netscan'`
Enter
Sleep 2000ms
Show

# Land on Targets. Tab through all four tabs to showcase the UI.
Sleep 1200ms
Tab
Sleep 900ms
Tab
Sleep 900ms
Tab
Sleep 1200ms

# Landed on History — the seeded scan is selected. Open its topology.
Type "T"
Sleep 3500ms

# Close and quit.
Escape
Sleep 300ms
Type "q"
Sleep 400ms
