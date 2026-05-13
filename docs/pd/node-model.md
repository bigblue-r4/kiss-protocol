# Harborlight PD — Node Model

## What is a node?

A **node** is a named installation of `witness-pd` at a physical or logical location. Examples:
- `evidence-room-1` — primary evidence room terminal
- `forensics-lab` — lab processing station
- `court-liaison` — transfer point for court submissions
- `archive-storage` — cold storage location

Nodes are string identifiers set at `witness-pd init --node <id>`. They appear in custody events as `from_node` and `to_node`.

## Multi-node deployments

Each node runs its own `witness-pd` instance with its own encrypted log and machine-ID-derived key. Logs are not shared between nodes.

Evidence transfers between nodes are recorded on each node independently:
- The sending node records a `transfer` event with `to_node`
- The receiving node records an `intake` event (or its own `transfer` event)

For a legally complete chain of custody, export bundles should be collected from all nodes involved in a case and presented together.

## Planned: multi-node sync

Future: a central aggregation node that pulls audit logs from all nodes and provides a unified chain-of-custody view across the department. This would use the same SGAIL remote sync protocol as the general Witness edition.

For the current release, multi-node coordination is manual — use the CLI export from each node and combine at the court liaison.

## Node naming conventions

Recommended: `<location>-<type>-<number>`

Examples:
- `hpd-evidence-001`
- `hpd-lab-001`
- `hpd-court-001`

Keep node IDs stable after initialization — they appear in all custody events. Changing a node ID after deployment creates a visible discontinuity in the custody chain.
