# Third-party agent tools (vendored)

Copies of open-source (MIT) repositories, pinned to the commit that was reviewed
before being added. Update them by re-copying from upstream after re-reviewing.

| Tool | Upstream | Commit | Where | Type |
|---|---|---|---|---|
| stack-diagram | https://github.com/caru-ini/stack-diagram | `75dbd3e` | `.claude/vendor/stack-diagram` → skill `stack-diagram` | Claude skill |
| claude-animation-skills | https://github.com/artemnovitckii/claude-animation-skills | `5dbea55` | `.claude/vendor/claude-animation-skills` → skills `graph`, `breakdown`, `map-route`, `minimalistic-graphics`, `stick-figure`, `zach-d-films` | Claude skills |
| spam-nuke | https://github.com/menhguin/spam-nuke | `5a8e970` | `.claude/vendor/spam-nuke` → skill `spam-nuke` | Claude skill |
| lanshu-infinite-stream-koubo | https://github.com/cclank/lanshu-infinite-stream-koubo | `dad073d` | `.claude/vendor/lanshu-infinite-stream-koubo` → skill of the same name (demo `.mp4`/`.gif` files left out) | Claude skill |
| proof-of-green | https://github.com/BekirEfeoglu/proof-of-green | `539f28d` | `.claude/vendor/proof-of-green` (tests/docs left out) | Claude Code hooks — **not enabled yet**, see below |
| uncut | https://github.com/Balanov/uncut | `d5c9528` | `tools/uncut` | Go CLI (coding-agent harness) |
| meu-emprego-novo | https://github.com/R238Company/meu-emprego-novo | `04e0e95` | `tools/meu-emprego-novo` | Python app (CrewAI + AWS Bedrock) |
| lead-scoring-agent | https://github.com/Catherine-zhang0422/lead-scoring-agent | `8d2d364` | `tools/lead-scoring-agent` | Python app |

Skills are symlinked from `.claude/skills/`, so Claude Code picks them up automatically in this project.

## One-time setup per machine

- **Animation skills** need ffmpeg, Node 18+ and Python 3.9+:
  `bash .claude/vendor/claude-animation-skills/kit/setup.sh` (add `--voice` for `/stick-figure` and `/zach-d-films`, ~1 GB of models).
  Don't run its `install.sh` — that links the skills into `~/.claude/skills`, which this project already does.
- **lanshu-infinite-stream-koubo**: `pip install -r .claude/vendor/lanshu-infinite-stream-koubo/requirements.txt` (numpy, optional).
- **stack-diagram**: Python 3; PNG export uses Playwright.
- **uncut**: needs Go 1.26+: `cd tools/uncut && go build -o uncut ./cmd/uncut`, then set `UNCUT_API_KEY` and `UNCUT_MODEL`.
- **meu-emprego-novo**: `pip install -r tools/meu-emprego-novo/requirements.txt`; needs AWS Bedrock credentials (see its README).
- **lead-scoring-agent**: `pip install -r tools/lead-scoring-agent/requirements.txt`. Note: at the pinned commit upstream
  `main.py` imports `parse_input_file` from `agent/parser.py`, which no longer exists, so the demo fails until upstream fixes it.

## Enabling proof-of-green

It blocks Claude from ending a turn when code changed and no test passed afterwards. Enable it by merging
`.claude/vendor/proof-of-green/project-hooks.json` into `.claude/settings.json` (or `.claude/settings.local.json`
to enable it only for yourself). Config options: `.proof-of-green.json` at the repo root (see its README).
