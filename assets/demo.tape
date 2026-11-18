# Charm VHS script — generates a crisp 15-second terminal GIF for DBShield
# Install VHS: https://github.com/charmbracelet/vhs
# Run: vhs assets/demo.tape

Output assets/demo.gif

Set Shell "powershell"
Set FontSize 16
Set Width 1100
Set Height 640
Set Padding 24
Set Theme "TokyoNight"
Set TypingSpeed 35ms

Hide
Type "function prompt { '$ ' }"
Enter
Type "function dbshield { node dist/cli.js @args }"
Enter
Type "Clear-Host"
Enter
Sleep 600ms
Show

Type "# 1. Inspect DBShield wire-protocol SQL firewall & MCP guardrails"
Enter
Sleep 400ms
Type "dbshield --help"
Enter
Sleep 3.5s

Type "Clear-Host"
Enter
Sleep 300ms

Type "# 2. Verify installed DBShield engine version"
Enter
Sleep 400ms
Type "dbshield --version"
Enter
Sleep 2s
