# Charm VHS script — generates a crisp 15-second terminal GIF for DBShield
# Install VHS: https://github.com/charmbracelet/vhs
# Run: vhs assets/demo.tape

Output assets/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1100
Set Height 620
Set Padding 20
Set Theme "TokyoNight"
Set TypingSpeed 40ms

Type "# 1. Audit SQL migrations & queries for destructive ops and missing WHERE clauses"
Enter
Sleep 600ms
Type `npx @ritualdev-lab/dbshield audit "DROP TABLE users CASCADE; DELETE FROM orders;"`
Enter
Sleep 2.5s

Type "# 2. Inspect wire-protocol firewall options (PostgreSQL Extended Query P/B/E)"
Enter
Sleep 600ms
Type "npx @ritualdev-lab/dbshield proxy --help"
Enter
Sleep 2.5s

Type "# 3. Check DBShield status & safety tiers"
Enter
Sleep 600ms
Type "npx @ritualdev-lab/dbshield --version"
Enter
Sleep 2s
