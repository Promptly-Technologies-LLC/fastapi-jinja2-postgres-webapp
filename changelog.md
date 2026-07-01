# Changelog

This changelog is generated automatically from [GitHub Releases](https://github.com/promptly-technologies-llc/fastapi-jinja2-postgres-webapp/releases).


# v1.0.2

*2026-06-30* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v1.0.2)


## What's Changed

- Fix ownership cascades during account deletion by [<span class="citation" cites="chriscarrollsmith">@chriscarrollsmith</span>](https://github.com/chriscarrollsmith) in https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/pull/210

**Full Changelog**: https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/compare/v1.0.1…v1.0.2


# v1.0.1

*2026-06-30* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v1.0.1)


## What's Changed

- Fix mobile layout by [<span class="citation" cites="rafizamankhan">@rafizamankhan</span>](https://github.com/rafizamankhan) in https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/pull/207
- Fix invalid token for logged-in users by [<span class="citation" cites="rafizamankhan">@rafizamankhan</span>](https://github.com/rafizamankhan) in https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/pull/208

**Full Changelog**: https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/compare/v1.0.0…v1.0.1


# v1.0.0

*2026-06-23* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v1.0.0)


## What's Changed

- ci: add semantic-release workflow and conventional commit enforcement by [<span class="citation" cites="chriscarrollsmith">@chriscarrollsmith</span>](https://github.com/chriscarrollsmith) in https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/pull/203

**Full Changelog**: https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/compare/v0.1.30…v1.0.0


# v0.1.30

*2026-06-23* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.30)


## Summary

- Add `InstrumentedAttribute[Any]` casts on all `selectinload` chains in `utils/core/organizations.py` per the SQLModel typing rule.
- Introduce `clear_all_rate_limiters()` and a session-wide autouse fixture in `tests/conftest.py` that resets limiters before and after every test.
- Remove duplicate module-local rate limiter reset fixtures from `tests/test_htmx.py` and `tests/routers/core/test_account.py`.

Closes [\#201](https://github.com/promptly-technologies-llc/fastapi-jinja2-postgres-webapp/issues/201)


## Test plan

`uv run ty check .`

`uv run pytest tests`

Made with [Cursor](https://cursor.com)


# v0.1.29

*2026-06-23* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.29)


## Summary

Resolves [\#196](https://github.com/promptly-technologies-llc/fastapi-jinja2-postgres-webapp/issues/196) by upgrading the full dependency lockfile to latest resolved versions, addressing Dependabot security alerts across runtime, dev, and transitive packages.

Key runtime upgrades: - `fastapi` 0.136.1 → 0.138.0 (`starlette` 1.0.0 → 1.3.1) - `pyjwt` 2.12.1 → 2.13.0 - `python-multipart` 0.0.29 → 0.0.32

Key dev/tooling upgrades: - `pytest` 8.4.2 → 9.1.1 (widened constraint from `<9.0.0` to `>=8.3.3`) - `pytest-jinja-check` 1.0.2 → 1.1.0 (Starlette 1.x `_IncludedRouter` route discovery) - `jupyter-server` 2.18.2 → 2.20.0 - `tornado` 6.5.5 → 6.5.7 - `bleach` 6.3.0 → 6.4.0


## Test plan

`uv run pytest tests` -- 421 passed

`uv run ty check .` -- passes

Confirm Dependabot alerts are cleared after merge (one `bleach` alert may remain if no upstream patch exists: GHSA-g75f-g53v-794x)

Made with [Cursor](https://cursor.com)


# v0.1.28

*2026-06-23* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.28)


## Summary

Two small, related cleanups to the communication-preferences feature added in [\#195](https://github.com/promptly-technologies-llc/fastapi-jinja2-postgres-webapp/issues/195):

1.  **Restore the confirm-password autocomplete regression test.** [\#195](https://github.com/promptly-technologies-llc/fastapi-jinja2-postgres-webapp/issues/195) accidentally deleted the `def` line for `test_register_page_confirm_password_has_autocomplete`, collapsing its body into `test_register_page_shows_password_requirements` and demoting its docstring to a no-op string statement. The issue [\#156](https://github.com/promptly-technologies-llc/fastapi-jinja2-postgres-webapp/issues/156) autocomplete check is restored as its own test. The comm-preference assertions remain in `test_register_page_shows_password_requirements`, where they correctly verify the register page renders the new fields.

2.  **Drop the `syncSubPreferences` helper.** In `communication_preferences_fields.html` the helper was only ever called from the master checkbox's `change` handler (disable branch) and never on init -- initial visibility is already set server-side via the Jinja `style="display: none;"` guard. Inlining it removes the indirection and the enable/disable asymmetry. Behavior is preserved exactly: enabling reveals the sub-preferences and checks `comm_updates`; disabling hides them and clears both sub-preferences.


## Test plan

`uv run pytest tests/routers/core/test_account.py` (91 passed)

`uv run pytest tests/test_templates.py` (30 passed)

Both `test_register_page_shows_password_requirements` and `test_register_page_confirm_password_has_autocomplete` are collected as separate tests

`uv run ty check .` clean


# v0.1.27

*2026-06-23* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.27)

Invalidates old invitation when prompted to send one to the same member within or after expiry without requiring cron jobs supporting cleanup.

Resolves [\#192](https://github.com/promptly-technologies-llc/fastapi-jinja2-postgres-webapp/issues/192)


# v0.1.26

*2026-06-23* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.26)

Added a cancel button to delete pending invitations.

Resolves [\#190](https://github.com/promptly-technologies-llc/fastapi-jinja2-postgres-webapp/issues/190)


# v0.1.25

*2026-06-07* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.25)

Wires the login "Remember Me" checkbox into auth cookie lifetime: unchecked logins get session cookies with a 12-hour refresh token, while checked logins get persistent cookies aligned to the existing 30-day refresh TTL. Cookie handling is centralized in set_auth_cookies() / clear_auth_cookies(), and the persistent flag is preserved through token rotation on /refresh and silent refresh via NeedsNewTokens. All auth paths keep httponly, secure, and samesite settings unchanged.

Resolves [\#187](https://github.com/promptly-technologies-llc/fastapi-jinja2-postgres-webapp/issues/187)


# v0.1.24

*2026-06-04* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.24)


## Summary

- Adds a modal-only conflict resolver to the propagate workflow for `pyproject.toml` and `uv.lock` conflicts.
- Preserves the Modal branch dependency overlay, regenerates `uv.lock`, and pushes the merge when only those known files conflict.
- Keeps the fallback PR path for all other conflicts.


## Test plan

- Simulated the current `origin/main` into `origin/modal` merge locally.
- Verified the resolver clears `pyproject.toml` and `uv.lock` conflicts.
- Verified the resolved `pyproject.toml` keeps `modal>=0.73.162` and `uv.lock` still contains the `modal` package.

Made with [Cursor](https://cursor.com)


# v0.1.23

*2026-06-04* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.23)


## Summary

- Disables matrix fail-fast for the propagate workflow so a conflict or fallback failure on one deployment branch does not cancel the other branch's propagation job.
- Leaves the existing GitHub App token flow in place; the app now has PR read/write permissions for fallback PR creation.


## Test plan

- Not run; workflow-only change.

Made with [Cursor](https://cursor.com)


# v0.1.22

*2026-06-04* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.22)

Confirm field re-validates against the current password; error clears when they match.

Resolves [\#182](https://github.com/promptly-technologies-llc/fastapi-jinja2-postgres-webapp/issues/182)


# v0.1.21

*2026-05-20* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.21)

Create Role Modal used to retain information from input and after role creation. Now the modal information is reset on cancel and after role creation.

Resolves [\#180](https://github.com/promptly-technologies-llc/fastapi-jinja2-postgres-webapp/issues/180)


# v0.1.20

*2026-05-20* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.20)

Fixed the modalDismiss handler in app.js to call bootstrap.Modal.hide() on any open modals before cleaning up backdrops, so the dialog properly closes after HTMX swaps the roles table.

Resolves [\#178](https://github.com/promptly-technologies-llc/fastapi-jinja2-postgres-webapp/issues/178)


# v0.1.19

*2026-03-18* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.19)


## Summary

- **Toast migration**: Replaced the custom `showToast()` JS function and client-side flash cookie reader with server-side rendering via `htmx-ext-remove-me` for auto-dismiss, HTMX `responseHandling` config for error-status OOB swaps, and a flash cookie middleware for full-page-load toasts.
- **Avatar update fix**: Replaced `HX-Refresh: true` on avatar upload with OOB swaps for both the profile display and navbar avatar. This eliminates the visible flicker from full page reloads and ensures the "Profile updated successfully" toast always appears (previously lost during refresh).
- **Navbar avatar partial**: Extracted the navbar avatar into a reusable partial (`navbar_avatar.html`) with an OOB variant (`navbar_avatar_oob.html`) for HTMX responses.


## Test plan

All 362 non-browser unit/integration tests pass

All 7 Playwright browser tests pass, including:

- `test_htmx_success_toast_appears` -- name-only profile update shows toast
- `test_avatar_update_toast_appears` -- avatar update shows toast
- `test_avatar_update_no_full_reload` -- avatar update uses OOB swaps, no page reload
- `test_htmx_error_toast_appears` -- error responses show toast via OOB
- `test_flash_cookie_toast_appears` -- flash cookies render server-side on load
- `test_toast_auto_dismisses` -- toasts auto-dismiss after 5s via remove-me
- `test_toast_close_button` -- manual close button works

🤖 Generated with [Claude Code](https://claude.com/claude-code)


# v0.1.18

*2026-03-18* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.18)


## Summary

Closes [\#175](https://github.com/promptly-technologies-llc/fastapi-jinja2-postgres-webapp/issues/175)

- Clear the "Add email" form field after successful submission using HTMX's `hx-on::after-request` event, with an `HX-Trigger` header from the server to signal success
- Order email addresses on the profile page with primary first via `ORDER BY is_primary DESC`, so the newly-promoted email always moves to the top row


## Test plan

`test_add_email_htmx_triggers_form_reset` -- verifies HX-Trigger header is returned on HTMX add-email requests

`test_profile_emails_ordered_primary_first` -- primary email with a higher row ID still renders before secondary

`test_profile_emails_ordered_primary_first_after_promote` -- newly promoted email appears first after swap

Full test suite passes (358 tests)

🤖 Generated with [Claude Code](https://claude.com/claude-code)


# v0.1.17

*2026-03-18* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.17)


## Summary

- **Multi-email system**: Users can add a secondary email (max 2), verify it via an emailed link, promote it to primary, or remove it. The old single-email update flow (`EmailUpdateToken`, `/request_email_update`, `/confirm_email_update`) has been removed.
- **Account recovery**: When a sensitive email change occurs (primary swap or email removal), the affected email receives a notification with a tokenized recovery link. Clicking it restores the victim's email as primary, purges attacker emails, revokes all sessions, and forces a password reset.
- **Password reset auto-login**: After resetting a password, the user is automatically logged in and redirected to the dashboard -- no redundant login step.
- **Flash cookie encoding fix**: URL-encode the JSON cookie value before setting it, preventing Python's `http.cookies` from mangling commas (`\054`) and breaking client-side `JSON.parse()`.
- **NeedsNewTokens query string preservation**: The token-refresh redirect now uses `str(request.url)` instead of `request.url.path`, preserving query parameters for GET routes.


## QA checklist


### Add and verify a secondary email

Log in and navigate to profile page

Add a secondary email address via the form

Verify a "Verification email sent" toast appears

- *Note*: "Add email" field/button should clear/disable after submission

Check the secondary email inbox to verify verification link was sent

Click the verification link

Verify redirect to login page with success toast

After login, verify the new email appears on the profile page as verified (non-primary)

Verify the primary email received a "New email added" notification


### Promote a secondary email to primary

From profile page, click "Make Primary" on the verified secondary email

Verify a "Primary email updated" toast appears

Verify the profile page now shows the new primary email

- *Note*: Primary email should move to top row rather than just swapping labels

Check the OLD primary email inbox for a "Primary Email Changed" notification

Verify the notification contains a "Recover Your Account" button/link (not just "change your password")


### Remove a secondary email

Add and verify a secondary email, then click "Remove"

Verify a "Email address removed" toast appears

Check the REMOVED email inbox for an "Email Address Removed" notification

Verify the notification contains a "Recover Your Account" button/link


### Account recovery (after primary swap)

With a promoted secondary email as primary, click the recovery link sent to the old primary

Verify redirect to the password reset page with "Account recovered. Please set a new password." toast

Submit a new password

Verify auto-login: redirected to dashboard with "Password reset successfully." toast (no manual login required)

Navigate to profile and verify the original email is restored as the sole primary email

Verify the attacker's email has been removed from the account


### Account recovery (after email removal)

Remove a secondary email, then click the recovery link sent to that email

Verify the same recovery flow as above works (redirect to reset, auto-login, email restored)


### Recovery edge cases

Click an expired recovery link (\>7 days) -- should see an error, not a crash

Click a used recovery link -- should see an error

Click a recovery link with a bogus token -- should see an error


### Standard password reset (regression check)

Use "Forgot Password" flow to reset password

Verify auto-login after reset (redirect to dashboard, not login page)

Verify "Password reset successfully." toast appears on the dashboard


### Flash toast visibility (regression check)

Verify toasts appear on all redirect flows above (not silently swallowed)

Specifically test with both fresh sessions and expired sessions

🤖 Generated with [Claude Code](https://claude.com/claude-code)


# v0.1.16

*2026-03-14* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.16)


## Summary

- Add `RefreshToken` model with JTI tracking in the `private` schema for server-side refresh token validation
- Implement token rotation: each refresh token use revokes the old token and issues a new one
- Add reuse detection: replaying a revoked token revokes ALL tokens for that account (signals theft)
- Logout now revokes the refresh token server-side, not just deleting the cookie
- Email update flow revokes all old refresh tokens before issuing new ones
- Legacy tokens without JTI (pre-migration) are gracefully rejected, forcing re-login
- Fix misleading "new email address" text in email update form to correctly say "current email address"


## Test plan

7 new integration tests covering all security flows (register/login token creation, logout revocation, token rotation, reuse detection, legacy rejection, automatic dependency refresh)

Updated existing unit tests for new JTI-aware token API

All 298 tests pass (291 existing + 7 new)

Manual testing of register, login, logout, and email update flows

Closes [\#81](https://github.com/promptly-technologies-llc/fastapi-jinja2-postgres-webapp/issues/81)

🤖 Generated with [Claude Code](https://claude.com/claude-code)


# v0.1.15

*2026-03-14* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.15)

- The dashboard now has a dropdown that lets you select an organization (so you can interact only with the resources for that organization)
- `utils/app/models.py` now has an example/illustrative `OrganizationResource` data model, and this data model is automatically imported and set up with the rest of the DB


# v0.1.14

*2026-03-14* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.14)


## Summary

- Adds a GitHub Actions workflow that automatically merges `main` into `modal` and `hetzner` deployment branches on every push
- If merge conflicts arise, opens a PR instead so they can be resolved manually
- Uses the existing GitHub App token for authentication


## Test plan

Merge this PR and verify the propagate workflow runs

Confirm both `modal` and `hetzner` branches receive the latest `main` changes

Optionally introduce a deliberate conflict on a deployment branch to verify the fallback PR creation works

Closes [\#169](https://github.com/promptly-technologies-llc/fastapi-jinja2-postgres-webapp/issues/169)

🤖 Generated with [Claude Code](https://claude.com/claude-code)


# v0.1.13

*2026-03-14* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.13)

Enforces that:

- Templates contain no syntax errors
- Templates use `url_for` instead of hardcoded routes for all onsite links
- Routes pass all required context variables when rendering templates
- `url_for` calls all point at valid FastAPI routes


# v0.1.12

*2026-03-14* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.12)


## Summary

- Add `require_unauthenticated_client` dependency that wraps `get_optional_user` and redirects authenticated users to the dashboard via a new `AlreadyAuthenticatedError` exception handler
- Add `get_verified_account` dependency that wraps `get_authenticated_account` with email/password re-verification for sensitive operations like account deletion
- Update routes (`read_home`, `read_login`, `read_register`, `read_forgot_password`, `delete_account`) to use the new dependencies, removing duplicated check-and-redirect logic from route bodies

Closes [\#108](https://github.com/promptly-technologies-llc/fastapi-jinja2-postgres-webapp/issues/108)


## Test plan

Added unit tests for `require_unauthenticated_client` (authenticated raises, unauthenticated passes)

Added unit tests for `get_verified_account` (email mismatch, wrong password, success)

All 383 existing tests pass

🤖 Generated with [Claude Code](https://claude.com/claude-code)


# v0.1.11

*2026-03-14* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.11)

Release v0.1.11


# v0.1.10

*2026-03-14* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.10)


## Summary

- Enable Open Graph and Twitter Card meta tags via `_quarto.yml` for rich link previews on social media
- Add `site-url` for canonical URLs and automatic sitemap generation
- Add `description` frontmatter to all `.qmd` pages for `<meta name="description">` tags
- Improve alt text on homepage screenshot image

Closes [\#37](https://github.com/promptly-technologies-llc/fastapi-jinja2-postgres-webapp/issues/37)


## Test plan

Verify Quarto renders successfully with `quarto render`

Inspect generated HTML for `<meta name="description">`, `og:` tags, and `twitter:` tags

Confirm `sitemap.xml` is generated in `_docs/`

🤖 Generated with [Claude Code](https://claude.com/claude-code)


# v0.1.9

*2026-03-13* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.9)


# v0.1.8

*2026-03-13* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.8)

Resequenced deployment documentation to clarify that Modal requires separate Postgres deployment, but Hetzner does not.

- Digital Ocean PostgreSQL deployment is nested under Modal
- Removed a Supabase-related example since Supabase is not an explicit deployment target (yet)


# v0.1.7

*2026-03-13* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.7)

Template changes (templates/base/partials/header.html): 1. Added a mobile-only

- with plain Profile and Logout links inside the collapsible  
  section (only for authenticated users) 2. Wrapped the desktop avatar dropdown in d-none d-lg-flex so it's hidden on mobile 3. Kept Login/Register links visible on all screen sizes (not wrapped in d-none)

  The result: on mobile, authenticated users see Profile and Logout as regular nav items in the hamburger menu (no dropdown, no avatar thumbnail). On desktop, the avatar dropdown works as before.


# v0.1.6

*2026-03-13* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.6)

1.  The Register page now clearly states the requirements for passwords
2.  The error toast, if the user submits an invalid password, restates the requirements
3.  Using a suggested password on Chrome now auto-populates both password fields, not just one.


# v0.1.5

*2026-03-12* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.5)

- **Add Hetzner Cloud deployment docs and deployment branch note**
- **Add hcloud CLI installation to devcontainer setup**
- **Update all dependencies and pin dev postgres to v17**
- **Replace mypy with ty type checker and fix ruff lint issues**
- **chore: release v0.1.2 \[skip ci\]**
- **Error messaging standardization**
- **Type checks and lints**
- **Bugfixes for modal cleanup**


# v0.1.4

*2026-03-12* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.4)

OOB Toast (HTMX error handlers)

These all fire through the exception handlers in main.py.

CredentialsError (401 toast)

1.  Go to /account/login
2.  Enter a valid email format but wrong credentials
3.  Submit -- toast renders: "Invalid email or password"

RequestValidationError (422)

1.  Go to /account/login
2.  Leave both fields blank, submit
3.  Toast is rendered with validation messages

PasswordValidationError (422)

1.  Go to /account/register
2.  Fill in name/email, enter a weak password like abc, different confirm password
3.  Submit -- toast renders: "The passwords you entered do not match"

RateLimitError (429 toast)

1.  Go to /account/login
2.  Submit wrong credentials rapidly ~6 times (depends on your limiter config)
3.  Eventually toast renders: "Too many attempts…" with Retry-After

HTTPException (business logic errors)

1.  Log in, go to an org page
2.  Try to create a role with a name that already exists (e.g. "Owner")
3.  Toast: "A role with that name already exists"

StarletteHTTPException (404 toast via HTMX)

- Harder to trigger naturally. You can use browser devtools to fire an HTMX request to a non-existent route: `htmx.ajax('GET', '/nonexistent', {target: 'body', headers: {'HX-Request': 'true'}})`

OOB Toasts (HTMX success -- append_toast)

These return the partial content + an appended toast in the same response.

Profile update

1.  Log in, go to /user/profile
2.  Click Edit, change your name, Save
3.  Toast: "Profile updated successfully."

Role CRUD

1.  Go to an org page where you're Owner
2.  Create a new role -- toast: "Role created successfully."
3.  Edit that role's name -- toast: "Role updated successfully."
4.  Delete that role -- toast: "Role deleted successfully."

\[\] User role update

1.  On the org page, edit a member's roles (check/uncheck roles)
2.  Save -- toast: "User role updated successfully."

\[\] Remove member

1.  On the org page, remove a non-owner member
2.  Toast: "User removed from organization."

\[\] Send invitation

1.  On the org page, invite a new email address
2.  Toast: "Invitation sent successfully."

Email update (HTMX path)

1.  On /user/profile, enter a new email in the Update Email form
2.  Submit -- toast: "Confirmation email sent. Check your inbox."

------------------------------------------------------------------------

Flash Cookie (PRG redirects -- full page load)

These set a flash_message cookie that the JS in base.html reads on the next page load.

Confirm email update

1.  Trigger an email update from profile
2.  Click the confirmation link from the email
3.  You'll be redirected to /user/profile -- toast: "Your email address has been successfully updated."

\[\] Forgot password

1.  Go to /account/forgot_password (or use the Change Password section on profile)
2.  Submit your email
3.  Redirected to ?show_form=false -- toast: "If an account exists with this email, a password reset link will be sent."

Update organization name

1.  On the org page, edit the org name and save
2.  Page redirects via HX-Redirect -- toast: "Organization updated successfully."

Delete organization

1.  On the org page, delete the organization
2.  Redirected to /user/profile -- toast: "Organization deleted successfully."

JS showToast() (client-side validation)

Avatar file validation

1.  Go to /user/profile, click Edit
2.  Try uploading a file that's too large -- toast: "File size must be less than X MB"
3.  Try uploading a .txt file -- toast: "File format must be one of: …"
4.  Try a very small image (e.g. 1x1 px) -- toast: "Image dimensions must be at least …"

------------------------------------------------------------------------

Quick checklist

┌────────────────┬─────────────────────────────────────────────┬────────────────────────────────┐ │ Mechanism │ Trigger │ Where to look │ ├────────────────┼─────────────────────────────────────────────┼────────────────────────────────┤ │ toast_response │ Any HTMX error (login, register, │ Bottom-right toast │ │ │ validation) │ │ ├────────────────┼─────────────────────────────────────────────┼────────────────────────────────┤ │ append_toast │ Any HTMX success mutation (profile, roles, │ Bottom-right toast alongside │ │ │ members, invitations) │ updated partial │ ├────────────────┼─────────────────────────────────────────────┼────────────────────────────────┤ │ Flash cookie │ PRG redirects (email confirm, forgot │ Bottom-right toast after page │ │ │ password, org update/delete) │ load │ ├────────────────┼─────────────────────────────────────────────┼────────────────────────────────┤ │ showToast() JS │ Avatar file picker validation │ Bottom-right toast, no network │ │ │ │ request │ └────────────────┴─────────────────────────────────────────────┴────────────────────────────────┘


# v0.1.3

*2026-03-12* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.3)


## Summary

- Set `follow_redirects=False` on all `TestClient` instances in `conftest.py` instead of passing it per API call
- Removed ~90 redundant `follow_redirects=False` arguments from individual test calls
- Added redirect location assertions (`response.headers["location"]`) to all tests that check 3xx status codes but previously didn't verify the redirect target
- Fixed `InsecureKeyLengthWarning` by using a test `SECRET_KEY` longer than 32 bytes

Closes [\#101](https://github.com/promptly-technologies-llc/fastapi-jinja2-postgres-webapp/issues/101)


## Test plan

All 348 tests pass with zero warnings

🤖 Generated with [Claude Code](https://claude.com/claude-code)


# v0.1.2

*2026-03-12* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.2)


## Summary

- Add Hetzner Cloud deployment documentation to deployment.qmd with instructions for provisioning, DNS setup, configuration, and management
- Add callout note explaining that deployment artifacts live on per-target branches (`modal`, `hetzner`)
- Add `DOMAIN` env var to `.env.example` for Caddy TLS configuration
- Install `hcloud` CLI in devcontainer setup

Closes [\#151](https://github.com/promptly-technologies-llc/fastapi-jinja2-postgres-webapp/issues/151)

🤖 Generated with [Claude Code](https://claude.com/claude-code)


# v0.1.1

*2026-03-11* · [GitHub](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/releases/tag/v0.1.1)


## Summary

- Adds a new `.github/workflows/release.yml` that runs on pushes to `main`
- Automatically bumps the patch version in `pyproject.toml`, syncs `uv.lock`, creates a GitHub release with PR body as release notes, and commits the version bump back to `main`
- Uses `[skip ci]` in the version bump commit to prevent infinite workflow loops

Closes [\#111](https://github.com/promptly-technologies-llc/fastapi-jinja2-postgres-webapp/issues/111)


## Test plan

Verify the workflow runs successfully on the next merge to `main`

Confirm a GitHub release is created with the correct tag and release notes

Confirm the version bump commit appears on `main` with `[skip ci]`

🤖 Generated with [Claude Code](https://claude.com/claude-code)
