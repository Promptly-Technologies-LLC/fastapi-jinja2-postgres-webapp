---
name: Red-green testing discipline
description: Always write a failing test (red phase) before applying a bug fix so the fix is validated
type: feedback
---

Always write a failing test that surfaces the bug before applying the fix. Running tests after a fix without a red-phase test doesn't prove anything.

**Why:** The user expects disciplined red-green-refactor workflow. A test that only exists after the fix could be passing for the wrong reason.

**How to apply:** When fixing a bug, first add or update a test that fails with the current code, confirm it fails, then apply the fix and confirm it passes.
