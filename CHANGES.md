## Version (2026101600)
- Improvement: Support Moodle 5.2 and 5.3 (`$plugin->supported = [500, 503]`). The code was checked against Moodle 5.3 for removed or deprecated APIs.
- Improvement: Remove the fallback to the deprecated `kill_user_sessions()`; the plugin requires Moodle 5.0, which always has `destroy_user_sessions()`.
- Improvement: Fix coding style so the Moodle Plugin CI codechecker passes (phpcbf with the moodle standard, no functional changes).
- Improvement: Update the privacy provider test for PHPUnit 11 (Moodle 5.3): use a `CoversClass` attribute instead of `@covers`, and `assertEqualsCanonicalizing()`.

## Version (2025041700)
- Bugfix: Fix scheduled task #1
