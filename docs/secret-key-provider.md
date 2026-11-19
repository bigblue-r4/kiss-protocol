# Secret-backed encryption foundation

Status: internal foundation only. No CLI or daemon uses this provider yet.
Existing genesis, logs, readers, backups, and machine-derived key behavior are
unchanged. This is not a completed encryption migration or hardware provider.

## Provider contract

`internal/keymaterial` supports Linux and macOS:

- `CreateFile(path)` generates 32 cryptographically random bytes into a new
  owner-only file, synchronizes the file and parent directory, and refuses to
  replace any existing path, including a symlink. It does not create parents.
  An error may leave a new file; inspect it explicitly rather than overwriting
  it or automatically treating it as an initialized key store.
- `LoadFile(path)` loads a regular file of exactly 32 raw bytes, owned by the
  effective user or root, with no group or other permission bits. Mode `0400`
  or `0600` works. It rejects final-component symlinks, directories, FIFOs,
  missing files, wrong lengths, and unsafe permissions. The opened descriptor
  is checked; loading does not create, repair, or replace a key. A FIFO cannot
  block the open indefinitely. No machine-ID fallback exists in this provider.
- Loading returns two 32-byte keys, derived with HKDF-SHA256, a nil salt, and
  distinct info strings `witness-secret-v1/encryption` and
  `witness-secret-v1/tree-head-mac`. The secret itself must have random entropy;
  a machine ID or human password is not a suitable substitute.

All ancestor directories must be trusted and protected against untrusted
writes. Parent symlinks are not prohibited. File checks do not defend against
a malicious root account, a compromised process running as the owner, or
concurrent secret modification by an authorized writer. Process memory contains
the secret and derived keys. Clearing temporary buffers is best effort, not a
guarantee that Go runtime copies have been erased.

The file provider is software custody. It makes no hardware-backed or
non-exportability claim. Provisioning into systemd credentials can supply an
owner-only file to a service, but integration and recovery must be tested before
deployment. A root-controlled credential file can be read by root.

## Required integration before production use

The existing store uses one legacy key for encryption and the tree-head MAC.
Substituting either returned key at one call site will break compatibility.
The next change must introduce an explicit, authenticated format/provider
selection and separate encryption/MAC inputs throughout the store, genesis,
witness, enforcer, gate, exports, and verification paths. Failures must never
select the legacy provider or initialize replacement data automatically.

Migration must authenticate original records, retain logical entries and their
Merkle roots, recompute new-format authentication material, coordinate all
readers and writers, and switch between complete generations with tested crash
recovery. Independently retained checkpoints must remain verifiable. No
automatic migration should run during ordinary log open.

Before migrating, establish recovery custody and retention for the original
secret and immutable backups. Demonstrate restoration on a replacement machine,
power-loss behavior, missing/wrong-key failures, concurrent-reader behavior,
rotation, and hardware-provider outage/replacement where applicable. Hardware
sealing and independent checkpoint continuity remain separate work items.
