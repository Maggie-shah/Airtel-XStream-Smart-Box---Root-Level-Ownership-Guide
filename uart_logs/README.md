# UART boot captures — Skyworth HY00A

Captures from the MBOOT-intercept attempts documented in README Appendix 10
(MBOOT UART Hunt). Hardware: 3.3V TTL @ 115200 8N1, **PCB requires solder
jumpers on RX/TX traces** (they ship open — see README Step 1).

| File | Contents |
|---|---|
| `uart_hunt1.raw/.txt` | Round 1 — Enter-hammer. Shows boot-ROM → CALDR → "Android Launcher (OTA Check Status)" → LZMA-uBoot verify/launch chain. No `Hit any key` banner: autoboot delay = 0. |
| `uart_hunt2.raw/.txt` | Round 2 — 8-key cycle every 500 ms. Keystrokes visibly land in the booted Android `sh` (`console:/ $`) proving UART is the OS console. |

Key excerpts (both rounds): `Hello CALDR_Entry-Begin`, `[OTA Stage = 0x0]
[Do not OTA] verify and launch uboot...`, `LZMA Decompression...ok`,
`Start Launch Application(lzma uboot)!!`.

Conclusion: no MBOOT stop window found via key interrupts; UART remains the
reliable rescue console. Details + dead ends in README Appendix 10.
