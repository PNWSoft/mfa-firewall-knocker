# Assets

## door_knocker.png

The lion's-head door knocker used for the application icon and the login-page logo.

**Licence: CC0 1.0 (public domain dedication).** No attribution is required, and it may be
used commercially. This matters because the project code is MIT — a graphic under a
non-commercial or share-alike licence would have made the repository awkward to reuse, which is
why this image replaced the original one.

`door_knocker.png` is the full-resolution source (1541×1541, 32-bit RGBA, transparent
background). It is kept so the derived assets can be regenerated rather than reverse-engineered.

## Regenerating the derived assets

Everything below is produced from `door_knocker.png`:

| File | What it is |
|------|-----------|
| `MFAWeb/knocker.ico`, `MFAService/knocker.ico`, `MFAAdmin/knocker.ico` | `ApplicationIcon` for each executable |
| `MFAWeb/wwwroot/favicon.ico` | browser tab icon (identical file) |
| `MFAWeb/wwwroot/knocker.png` | 256×256 logo shown on the login page when `LogoUrl` is empty |

The `.ico` holds six sizes — 16, 32, 48, 64, 128, 256 — each **PNG-compressed** rather than
stored as a raw BMP. That keeps it at ~111 KB instead of ~370 KB with no visible difference;
PNG-in-ICO is supported by Windows Vista and later, and this project targets Server 2019+.

Two things to preserve if you regenerate:

- **Keep the transparent background.** The login page renders the logo on a dark panel
  (`#1e1e1e`); an opaque background shows as a visible box.
- **Keep the 256×256 entry.** It is what the login page serves and what Explorer uses for large
  icon views.

Note that `System.Drawing.Icon` will not load a PNG-compressed 256×256 entry and silently falls
back to 128 — that is a limitation of that specific API, not of the file. Windows resource
embedding and browsers both handle it correctly. Verify a rebuilt icon by checking that all six
entries parse and that the compiled executable contains six icon blobs, not by round-tripping
through `System.Drawing.Icon`.
