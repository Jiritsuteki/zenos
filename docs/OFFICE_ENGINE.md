# Office files in ZENOS: the LibreOffice engine under ZENOS's rules

Status: in the source, not released.

## Why

ZENOS's first office apps (apps/docs, apps/sheets, apps/slides) read Word and Excel files into their own simple
models. Measured on public files from Japanese ministries and municipalities (tests/office, 31 Oct 2026), they kept
text, values and formulas but lost every table, picture, header and footer, vertical text, merged cell and print
area, and could not open old .doc files. Reaching Office compatibility by writing our own readers would take years.
The engine that already does it is LibreOffice (MPL-2.0). ZENOS hands file reading, writing and drawing to it, and
keeps for itself what the engine does not do: where the file lives, what may leave the document, printing, the
network.

## The parts

- `system/lib/zoffice.py`: open, save and convert (docx, doc, xlsx, xls, pptx, ppt, pdf). LibreOffice runs in the
  ZENOS sandbox (bubblewrap: an empty root, /usr /etc /opt read-only, no network, no home folder, the seccomp
  filter). The file comes in on stdin and goes out on stdout; inside the sandbox it lives in a tmpfs only. The
  profile is locked down with LibreOffice's own configuration keys, finalized: macros never run
  (`DisableMacrosExecution`, `MacroSecurityLevel` 3), no update check, no autosave or recovery copies, no backup
  copies, no lock files, no crash reports, no extension installation. A file that claims a package format (docx,
  xlsx, pptx) must be one.
- `apps/office/zenos_office.py` and `apps/office/zenos-office`: the window. The engine draws and edits the document
  through LibreOfficeKit's GTK view (LOKDocView, Debian packages `liblibreofficekitgtk`, `gir1.2-lokdocview-0.1`),
  inside a ZENOS window started in bubblewrap with no network, the system read-only, only the document's folder
  writable. The document is copied into a tmpfs (`$XDG_RUNTIME_DIR`) and removed when the window closes.
  - Copying out: the engine's own clipboard stays inside the view (Ctrl+C never reaches the system clipboard,
    tested). Text leaves only through the window's Copy, which is refused from L3 up.
  - Printing: the engine never prints. Pages are made as PDF from the saved copy, in a separate sandbox, and go to
    ZENOS's print path, which keeps its limits and banner.
  - Saving: the engine writes the file in its own format (Word stays Word); the window writes it back to where it
    came from. Sealed files are to go back through the vault and be sealed again (not wired yet).

## Choices, and the ones not taken

| | Chosen: LOKDocView in a ZENOS window | LibreOffice's own windows | Collabora Online (CODE) | ONLYOFFICE |
|---|---|---|---|---|
| Engine | LibreOffice | LibreOffice | LibreOffice (Collabora's branch) | its own |
| Copy out controlled by ZENOS | yes: only through the window | no clipboard key in the configuration; commands can be hidden, not enforced | per document (`DisableCopy`) | not checked |
| Printing controlled by ZENOS | yes: the engine never prints | `.uno:Print` can be hidden only | `DisablePrint`, `DownloadAsPostMessage` | not checked |
| Packages | Debian | Debian | not in Debian; Collabora's own builds | not in Debian |
| Terms | MPL-2.0 | MPL-2.0 | source MPL-2.0; CODE builds "not recommended for production environments" (collaboraonline.com/code) | AGPL-3.0 with additional terms |
| Network | none (sandbox) | none (sandbox) | a server (coolwsd) with an update check (`fetch_update_check`) | a server |

LibreOffice's own windows were not chosen because ZENOS could not enforce the L3+ rules there: the configuration
has no key for the clipboard, and hiding a menu entry is not a rule. Collabora Online was not chosen for now: it is
a server for many users with its own jails and a storage host, its CODE builds are meant for testing and home use,
and building it ourselves from source is a larger step than a desktop window needs. Its per-document permission
model (WOPI `DisableCopy`, `DisablePrint`, `WatermarkText`) is the reference if ZENOS later needs editing in a
browser. ONLYOFFICE was not chosen: it does not use the LibreOffice engine, it is AGPL-3.0 with additional terms,
and it is not in Debian.

Known limits of LibreOfficeKit: the tile and clipboard parts of its C API are marked unstable
(`LOK_USE_UNSTABLE_API`), so the LibreOffice version is pinned with the release and checked by the tests; it cannot
load a document from memory, so the document is placed in a tmpfs; LOKDocView is GTK 3, like the rest of ZENOS's app
windows (WebKitGTK 4.1).

## How it is measured

`tests/office` opens and saves public files from ministries and municipalities with each engine and compares the
saved file with the original: every element counted (tables, pictures, headers and footers, vertical text,
distributed alignment; merged cells, borders cell by cell, column widths, print areas, page breaks, conditional
formats and input rules by the cells they cover, formulas, number formats, fonts, fills; slides, charts, tables),
cell values and formulas, and the pages drawn as images. `zenos` is this engine. The drawing of pages is
LibreOffice's own; Microsoft Office is not used in the check, so "looks alike" means alike after saving, not alike
in Microsoft Office.

## Not built yet

- The window's own toolbar, menus, sheet tabs and slide list, designed in Figma first and reviewed before anything
  ships. The window today has Copy, Save and PDF only; editing is the engine's (keyboard and mouse in the page).
- Sealed files through the vault (open into the tmpfs, seal again on saving), and the print path wired to the
  window.
- Opening Office files from the file manager and the old apps with this window.
- Fonts with the same widths as the fonts the files ask for (MS Mincho, MS Gothic, Yu Mincho, Calibri ...): the
  replacements decide line breaks and page breaks.
- A comparison against Microsoft Office itself (needs Microsoft Office).
