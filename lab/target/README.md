# lab/target

The concrete, harmless local directory `lab-agents`' attacker/defender
operate on — declared as the sole real target in `lab/scope.toml`.

Entirely contained within this Codespace's own ephemeral container
filesystem: not a cloud resource, not shared with any other environment,
and gone whenever this Codespace is. Nothing outside this directory is
in scope for any lab-agent file or command operation — enforced
structurally by `host::evaluate`'s path-containment check (see
`host/src/broker.rs`), not just documented here.

Anything a real lab run writes here is gitignored — only this file is
tracked, to keep the directory (and its purpose) present in version
control without committing runtime output.
