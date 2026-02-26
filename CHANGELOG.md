# Changelog

## v1.0.10 - 2026-02-26

### Fixed
- `AuthenticationAnalyzer` no longer false-positives on nested public route URIs (e.g. `/auth/login`, `/api/v1/register`) — the public-route regex now allows path segments before the keyword
- `AuthenticationAnalyzer` no longer false-positives on dotted public route names (e.g. `auth.login`, `admin.auth.register`) — the route-name regex now allows dotted prefixes
- Recommendation text now mentions the `public_routes` config option as an alternative to `->middleware("guest")`

## v1.0.9 - 2026-02-25

### Fixed
- `SqlInjectionAnalyzer` no longer false-positives on table/column name concatenation in `*Raw()` fragment methods (e.g. `->orderByRaw('(col/' . $table . '.goal) ASC')`) — only direct user input sources (`$_GET`, `$_POST`, `request()`, `Request::input()`) are flagged (#97)
- `SqlInjectionAnalyzer` no longer false-positives on structural concatenation in `DB::select/insert/update/delete` when bindings are present (e.g. `DB::select('...IN (' . $placeholders . ')', $bindings)`) — the presence of bindings indicates parameterized query awareness (#97)

## v1.0.8 - 2026-02-25

### Fixed
- `MassAssignmentAnalyzer` recommendations no longer suggest `request()->validated()` as a universal alternative — clarified that `validated()` requires a `FormRequest` subclass, with `request()->only([...])` as the universal safe option (#96)

## v1.0.7 - 2026-02-24

### Fixed
- `HSTSHeaderAnalyzer` no longer false-positives on multi-line header definitions (e.g. `$response->headers->set(\n  'Strict-Transport-Security',\n  'max-age=31536000; includeSubDomains'\n)`) — now gathers a context window across subsequent lines (#95)
- `includeSubDomains` and `preload` directive checks are now case-insensitive per RFC 6797

## v1.0.6 - 2026-02-24

### Added
- `--triggered-by` option to `shield:analyze` for tracking how analysis was triggered (manual, ci_cd, scheduled)
- `--git-branch` and `--git-commit` options for attaching git context to reports
- `TriggerSource` enum for type-safe trigger source handling
- `total_issues` and `issues_by_severity` fields in report summary
- Report metadata enrichment: PHP version, environment, app name, OS, and git context

### Changed
- `Reporter` now resolves package version via `Composer\InstalledVersions` instead of parsing `composer.json`
- Report timestamps are always UTC
- Aligned platform API endpoints for forward compatibility

## v1.0.5 - 2026-02-24

### Fixed
- `XssAnalyzer` no longer flags literal-output ternaries inside `<script>` tags as JavaScript XSS (e.g. `{{ $coll->contains(request()->route()->getName()) ? 'true' : 'false' }}`) — both branches are string/boolean/numeric/null literals so the output can never contain user-controlled data

## v1.0.4 - 2026-02-23

### Fixed
- Remove `preload` from HSTS missing-header recommendation to match default config (`require_preload => false`) and avoid encouraging an irreversible browser preload list submission

## v1.0.3 - 2026-02-20

### Fixed
- `AuthenticationAnalyzer` now recognises `Route::middleware('guest')->group()` wrappers so routes inside guest groups are no longer false-positived as "missing auth middleware"
- Route groups using array syntax (`Route::group(['middleware' => 'guest', ...])`) are also recognised
- Controller methods pointed to by routes in guest groups are correctly marked as intentionally public
- Improved recommendation strings to mention `->middleware("guest")` as a valid alternative for intentionally public routes

## v1.0.2 - 2026-02-20

### Fixed
- Fix "Documentation URL:" never appearing in console output by using `getDocsUrl()` accessor instead of raw `docsUrl` property in `AnalyzeCommand`

## v1.0.1 - 2026-02-20

### Fixed
- Widen `larastan/larastan` from `^2.0` to `^2.0|^3.0` and `phpstan/phpstan` from `^1.10` to `^1.10|^2.0` to fix installation on Laravel 12 projects (#89)

## v1.0.0 - 2026-02-19

First stable release. Graduated from 14 pre-release versions (v0.1.0–v0.1.13).

### Highlights
- 73 production-ready analyzers across 5 categories
- PHPStan Level 9, 98%+ test coverage, Laravel 9–12 support

### Analyzers (73 total)
- 22 Security (OWASP Top 10 2021 coverage)
- 18 Performance
- 13 Reliability (includes PHPStan integration with 13 categories)
- 5 Code Quality
- 15 Best Practices

### Features
- `shield:analyze` command with category/analyzer/format/output filtering
- `shield:baseline` command for gradual adoption
- Baseline comparison (`--baseline`) — only report new issues
- Inline suppression (`@shieldci-ignore`) support
- Code snippets with syntax highlighting and env variable redaction
- Severity-aware results (resultBySeverity) for granular issue tiers
- CI mode for fast pipeline-friendly analysis
- Configurable fail conditions (severity threshold + score threshold)
- Don't-report list for informational-only analyzers
- Ignore-errors config with glob/wildcard pattern matching
- Environment mapping for multi-environment deployments
- Human-readable analyzer names in CLI output
- Laravel Vapor support (OpcacheAnalyzer, PHPIniAnalyzer)

### Quality
- AST-based analysis for security analyzers (migrated from regex)
- Extensive false-positive reduction (10+ analyzers improved)
- Passwordless project detection
- PHPStan Faker/Carbon/Eloquent scope handling
