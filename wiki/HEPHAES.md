# HEPHAES.md — wiki conventions for irminsul

This file is the **schema** for this wiki: it tells the LLM how the wiki is
structured and what workflows to follow. hephaes (and you) maintain it; humans
read the wiki and curate the questions. Co-evolve this file as conventions sharpen.

## Layers

- **Raw sources** — the repository's files (code *and* its own docs/config/data).
  Immutable. Read from them; never modify them.
- **The wiki** — this directory of generated markdown. The LLM owns it entirely.
- **The schema** — this file.

## Page taxonomy

Create pages of these types (set `type:` in frontmatter accordingly):

- `overview` → `overview.md` — the "start here" page: what the project is and its
  architecture at a glance. Written/last-revised after the other pages exist.
- `architecture` → `architecture/<subsystem>.md` — how a subsystem fits together.
- `module` → `modules/<module-or-package>.md` — one page per meaningful module,
  package, or directory: its responsibility, key types/functions, dependencies.
- `concept` → `concepts/<abstraction>.md` — key abstractions, domain concepts,
  recurring patterns that span modules.
- `flow` → `flows/<name>.md` — a request lifecycle, build pipeline, data flow.
- `decision` → `decisions/<name>.md` — design decisions mined from code/docs/commits.
- `answer` → `answers/<slug>.md` — answers to questions, filed back into the wiki.
- `glossary` → `glossary.md` — short definitions of project-specific terms.

Prefer a handful of high-signal pages over many thin ones. A page should earn its
place by capturing something a reader would otherwise reconstruct from the source.

## Frontmatter contract (every page)

```yaml
---
title: Human Title
type: module            # one of the types above
sources:                # source paths/globs this page is derived from
  - src/auth/**
  - src/middleware/session.ts
related:                 # use a YAML list (not inline) so frontmatter stays valid
  - "[[Session Handling]]"
  - "[[User Model]]"
summary: One-line description used in index.md.
updated: YYYY-MM-DD
source_commit: <short sha>   # repo state this page was last reconciled against
---
```

`sources:` is load-bearing — it is how `hephaes update` knows which pages a changed
file affects. Always fill it with the real paths/globs the page summarizes.

## Link discipline

- Link related pages with `[[wikilinks]]`. Link liberally.
- Every page should be reachable from `index.md`; avoid orphans.
- Cite source locations inline as `path/to/file.rs:42` so readers can jump to code.

## Special files

- `index.md` — content catalog (auto-rebuilt from frontmatter). Read it first.
- `log.md` — append-only history; entries start with `## [YYYY-MM-DD] kind | Title`.
- `HEPHAES.md` — this file.

## Workflows

**Ingest (init/update).** Read the repo map and relevant source files. For each
meaningful unit, create or update its page following the taxonomy and frontmatter
contract. When a source changed and contradicts an existing page, update the page
and note the change rather than silently overwriting. Keep `sources:` accurate.

**Query (ask).** Read `index.md`, open the relevant pages, and answer concisely
with citations to wiki pages and `file:line`. A good answer may be filed back as
an `answer` page so explorations compound.

**Lint.** Look for contradictions, stale claims, orphan pages, missing pages for
important concepts, broken `[[links]]`, and drift from the current source.

## Style

Concise and concrete. Favor lists and short paragraphs. Explain *why*, not just
*what*. Never fabricate behavior — read the source when unsure.
