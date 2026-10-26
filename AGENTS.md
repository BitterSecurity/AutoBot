# Change tracking and task isolation

Before opening or updating any PR, update the single root `CHAGELOG.md`, preserve
its history, link the PR and distinguish Unreleased work from actual publication.
Do not create a second differently named changelog. Source versions remain
sentinels until the repository's release workflow stamps a real immutable tag.

Fetch and confirm remote main for each task, then use a separate branch/worktree.
Preserve unrelated dirty work. Remove a merged task worktree only after checking
it is clean, pushed and unused by another active task.
