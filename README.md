# Model Pickle Scanner

Drop a .pt, .bin, .ckpt or .pkl and read its pickle opcodes in the browser without executing them, including exactly which global or opcode makes torch.load(weights_only=True) refuse the file.

## Live demo

https://0xelitesystem.github.io/model-pickle-scanner/

## Features

**Input artifact: a checkpoint file.** You give it bytes, it gives you two things.

**1. The permanent opcode and import inventory.** Every `GLOBAL` and `STACK_GLOBAL` the file
resolves, where it resolves it, and every `REDUCE`, `NEWOBJ`, `INST` or `OBJ` that would call one.
Offsets match `pickletools.dis`, so you can check the tool against the standard library.

**2. The verdict people actually want.** Since PyTorch 2.6 flipped `torch.load` to
`weights_only=True` by default, the practical question is not "does this file contain something
scary", it is "will this file even load". That question is reproducible, because
`torch/_weights_only_unpickler.py` exposes two finite, readable tables: an allowed-globals list and
the set of opcodes its read loop implements. The page reproduces the decision and names the exact
blocker, at a byte offset, in torch's own error wording.

Things that fall out of doing it properly:

- **A real pickle stack, not a text window.** `STACK_GLOBAL` pushes the module and the name as two
  separate stack items, so the import never appears as one contiguous token anywhere in the file. The
  page runs the stack, the memo, the mark stack and the metastack, and pops the two operands the way
  CPython does. A `STACK_GLOBAL` fed from `BINGET` therefore resolves too.
- **Rejection with no dangerous import at all.** The weights_only unpickler refuses *opcodes* as well
  as globals, and it implements only 34 of them. A perfectly ordinary protocol 4 pickle importing
  nothing but `collections.OrderedDict` is refused at `FRAME`, offset 2, before any import is
  reached. Load the "Protocol 4, allowlisted import only" sample and watch it happen. A scanner that
  only looks for dangerous imports calls that file clean.
- **CVE-2025-71325 shipped as a regression fixture.** GHSA-9gvj-pp9x-gcfr is picklescan's
  `STACK_GLOBAL` off-by-one: the backwards scan for the two operands looped `range(1, n)`, which
  never reaches op index 0, so a protocol 0 pickle with an operand at index 0 raised `ValueError` and
  the scan bypassed detection. Section 6 reimplements the pre-fix loop, the post-fix `range(1, n + 1)`
  loop and this tool's stack model, and runs all three on the advisory's exact 26-byte payload. Both
  halves of the 0.0.27 fix are modelled, not just the range: the same release added `STRING`,
  `BINSTRING` and `SHORT_BINSTRING` to the list of opcodes the scan accepts as string operands. The
  advisory's published offsets (0, 6, 16, 17, 23, 24, 25) are asserted in the self-tests. Reproducing
  the incumbent's hole here would go red.
- **Archive members, all of them.** A TorchScript archive carries `constants.pkl`,
  `callstack_debug_map.pkl` and one `code/<name>.py.debug_pkl` per source file, so every member named
  `*.pkl` or `*.debug_pkl` is walked, not just `data.pkl`. Extracted bytes are CRC32-checked against
  the central directory.
- **Legacy formats refused, not guessed at.** The non-ZIP `torch.save` layout and the older tar layout
  are recognised and declined with a reason. Half-parsing them would be worse than saying no.
- **Dated vendor data kept visually separate.** The torch tables live in their own amber, dashed panel
  with the pinned tag, the tag's release date and the transcription date. The verdict is stamped
  "against torch v2.13.0 tables" and is never a bare "safe" or "unsafe", because the allowlist grows
  every release.
- **37 self-tests you can run in the page**, including the CVE offsets, the ZIP64 field routing, the
  CRC32 check value, and an import literally named `constructor.__proto__`.

## How it works

**Reading the file.** A `.pt` written by `torch.save` is a ZIP. The page reads the last 66000 bytes
through `File.slice`, which covers a maximum-length archive comment plus the ZIP64 locator, finds
the end-of-central-directory record, walks the central directory, and then slices only the byte
ranges of the pickle members. Tensor storage records are never read, so a 14 GB checkpoint costs a
few kilobytes of disk transfer and never enters memory. ZIP64 is handled: when the classic record
carries the 0xFFFF or 0xFFFFFFFF sentinels the page follows the ZIP64 locator and record and reads
the 64-bit fields from the per-entry `0x0001` extra field.

**Decompression.** `PyTorchStreamWriter::writeRecord` declares `bool compress = false`, and every
call on the `torch.save` path takes that default, so a plain checkpoint's records are stored rather
than deflated and can be read as-is. TorchScript is the exception and the reason the deflate path is
not optional: `torch/csrc/jit/serialization/export_module.cpp` passes `size > kMinToCompress` with
`kMinToCompress = 200`, so source files and `.debug_pkl` records over 200 bytes are deflated. Those
go through `DecompressionStream("deflate-raw")`, which MDN documents as decompressing "using the
DEFLATE algorithm without a header and trailing checksum" and marks as available across browsers
since May 2023. No bundled inflate, no wasm, no external dependencies.

**Disassembly.** An opcode table transcribed from CPython's `Lib/pickle.py`: all 68 opcodes defined
across protocols 0 through 5, none omitted. Every argument encoding is read explicitly, so the walk
always knows how many bytes an opcode consumes. On an unknown opcode byte it stops and says so
rather than guessing a length and producing fiction.

**The weights_only decision.** Torch reads an opcode byte before it can look at anything else, so the
opcode gate is evaluated first, then the Python 2 to 3 rename tables are applied to a `GLOBAL`
(`__builtin__.intern` becomes `sys.intern`, which is then blocked by module), then the blocklist,
then the allowlist, then the "must be imported" special cases. Torch raises on the first problem, so
that one is the headline and the rest are listed as what you would hit next. You can simulate
`torch.serialization.add_safe_globals` in the UI, and watch the four blocklisted modules refuse to be
re-allowed by it.

**Architecture.** The disassembler, the weights_only evaluator, the picklescan reimplementation and
the ZIP parsers are pure functions that take plain values and return plain result objects. None of
them touch `document` or `window`. They can be lifted out of the page and run in Node unchanged,
which is how the fixtures in this repo were checked against Python's `pickletools`.

**What it does not decide.** Several of torch's checks depend on runtime object types, which no static
reader can know: the `BUILD` target type, the `APPEND` and `APPENDS` list check, the `SETITEM`
container check, and the `BINPERSID` persistent-id shape. If your file only trips one of those, this
page will say "no blocker found" and torch will still refuse. That gap is stated on the page itself,
not buried. And a file that `weights_only=True` accepts is not thereby a file to open with
`weights_only=False`.

**Primary sources.** Every external claim on the page carries a link and, where it matters, a quote:
`torch/_weights_only_unpickler.py`, `torch/serialization.py`, `caffe2/serialize/inline_container.h`,
`torch/csrc/jit/serialization/export_module.cpp` and `torch/csrc/utils/tensor_types.cpp` at tag
v2.13.0; the PyTorch 2.6.0 release notes; the GitHub advisory for CVE-2025-71325; picklescan's own
`scanner.py` at v1.0.5 and at the vulnerable commit; CPython's `Lib/pickle.py`; MDN on
`DecompressionStream()`; and PKWARE's APPNOTE.TXT for the ZIP records.

One thing the page corrects rather than repeats: `torch.load`'s signature is
`weights_only: bool | None = None`, not `True`. `_default_to_weights_only()` resolves `None` to
`True` only when `pickle_module is None` and the build is not fbcode, so passing a `pickle_module`
silently opts you back out of the check this whole page is about.

## Privacy

Everything runs in your browser tab. Your checkpoint is never uploaded, never sent anywhere and never
executed. The page makes no network requests at all: there are no external dependencies, no fonts, no
analytics and no API key. Files are read through `File.slice`, so only the byte ranges the tool
actually needs are ever read off disk. Strings pulled out of a pickle are rendered as printable ASCII
with escapes, so a module name carrying control characters or a bidi override cannot disguise itself
in the output.

## License

MIT. See [LICENSE](LICENSE).

## More

- https://0xelitesystem.github.io/
- https://elitesystem.ai
