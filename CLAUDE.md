# Claude contributor guidance

Read and follow `AGENTS.md`; it is the canonical policy for all automated contributors.

Start with `docs/project/current.md`, then use `docs/context/index.md` to load the smallest
task-relevant context pack. Keep generated changes bounded, inspectable, and easy to revert. Do
not claim that a candidate is improved or safe without evidence from an independent evaluation
path. Run `bash scripts/verify.sh` before presenting a change as complete.
