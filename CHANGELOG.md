# Changelog

## v1.5.4 - 2026-03-07

### Fixed
- `FillableForeignKeyAnalyzer` now reports each issue at the specific `$fillable` array item line (e.g. `'user_id',`) instead of the `protected $fillable = [` declaration line — fixes `@shieldci-ignore` comments placed on the offending entry being silently ignored
- `NamingConventionAnalyzer` now reports property violations at the individual property line (`$prop->getStartLine()`) and constant violations at the individual constant line (`$const->getStartLine()`) instead of the parent statement line — same inline-suppression fix applies
- `PasswordSecurityAnalyzer` now reports weak `password_hash()` option issues (`bcrypt cost`, `argon2 memory_cost`, `time_cost`, `threads`) at the offending array item line instead of the `password_hash(` call line

## v1.5.3 - 2026-03-07

### Fixed
- `CsrfAnalyzer` no longer false-positives on route files registered with `web` middleware externally via `withRouting(then: ...)` in `bootstrap/app.php` (e.g. `Route::middleware('web')->group(base_path('routes/auth.php'))`) — these files inherit CSRF protection from the middleware group and are now correctly skipped
- `LoginThrottlingAnalyzer` no longer false-positives on login routes in the same externally-registered route files — throttle applied globally to the `web` group is now respected

### Added
- `BootstrapRouteParser` support class (`ShieldCI\Support`) — AST-based utility that detects route files covered by the `web` middleware group through external registration; checks both `require`/`include` statements in `routes/web.php` and `Route::middleware('web')->...->group(base_path(...))` chains in `bootstrap/app.php`; used by `CsrfAnalyzer` and `LoginThrottlingAnalyzer`

## v1.5.2 - 2026-03-06

### Fixed
- `AuthenticationAnalyzer` now correctly recognises custom auth middleware classes applied at the group level via `Route::middleware(ClassName::class)->group()` — the class name was previously unresolved due to a NameResolver timing issue in single-pass traversal
- `AuthenticationAnalyzer` now correctly inherits middleware from multi-segment route chains such as `Route::prefix('api')->middleware('auth')->group()` — intermediate method calls between the `Route::` static call and `->group()` are now walked correctly
- `AuthenticationAnalyzer` now correctly maps legacy string-format route handlers (`'Controller@method'`, `'Controller'`) to controller methods for auth-stat tracking

### Changed
- `AuthenticationAnalyzer` route file analysis fully migrated from regex/line-based parsing to PHP-Parser AST via a new `RouteAuthVisitor` — 17 regex methods removed; all valid PHP formatting variants (multiline chains, different indentation, etc.) are now handled without fragility

## v1.5.1 - 2026-03-06

### Fixed
- `AuthenticationAnalyzer` no longer false-positives on invokable controllers registered on plain `Route::get()` routes (e.g. `PrivacyController`, `LandingController`) — unauthenticated GET routes now mark the target method as intentionally public, consistent with named resource actions `index`/`show`; POST/PUT/PATCH/DELETE routes without auth middleware continue to be flagged
- `AuthenticationAnalyzer` no longer false-positives on `FormRequest::authorize() => true` when the `FormRequest` is injected into an auth-gated controller action (route middleware, constructor middleware, or `middleware()` method) — only unprotected sensitive actions are flagged; orphaned `FormRequest` classes are also skipped
- `AuthenticationAnalyzer` no longer false-positives on `Auth::user()->`, `auth()->user()->`, or `$request->user()->` calls inside controller methods that are verifiably protected by auth middleware — suppression uses the already-computed `routeAuthStats` and `publicControllerMethods` maps (route-level) or constructor / `middleware()` method inspection (controller-level)

## v1.5.0 - 2026-03-05

### Added
- `--category` now accepts comma-separated values to run multiple categories in one pass (e.g. `--category=security,performance`)
- `AnalyzerManager::getByCategories(array $categories)` — filters the registered analyzer pool to any number of categories at once
- Warning emitted when both `--analyzer` and `--category` are provided simultaneously (`--category` is silently ignored in that case; the warning makes the precedence explicit)

### Changed
- `--category` help text updated to document comma-separated usage

## v1.4.0 - 2026-03-03

### Added
- `--ci` flag on `shield:analyze` — activates CI mode directly from the command line without any environment variable or config file change

### Changed
- CI mode is now activated exclusively via `--ci` on `shield:analyze` (and the existing `--ci` on `shield:baseline`); the `SHIELDCI_CI_MODE` env var path is removed

### Removed
- `ci_mode` key from `config/shieldci.php` — the `SHIELDCI_CI_MODE` environment variable is no longer read; use `--ci` instead (`ci_mode_analyzers` and `ci_mode_exclude_analyzers` remain unchanged)

## v1.3.0 - 2026-03-02

### Added
- `CiEnvironmentDetector::resolvePrNumber()` — auto-detects the pull-request / merge-request number from CI env vars across all 7 supported providers; GitHub falls back from `GITHUB_REF_NUMBER` to parsing `refs/pull/N/` from `GITHUB_REF`
- `CiEnvironmentDetector::resolveRepository()` — resolves `owner/repo` from CI env vars (GitHub, GitLab, CircleCI, Bitbucket, Travis CI; Azure DevOps and Jenkins are skipped — their vars don't reliably produce this format)
- `CiEnvironmentDetector::resolveBaseBranch()` — resolves the PR target branch from CI env vars; absent on non-PR builds
- `--git-pr-number`, `--git-repository`, `--git-base-branch` CLI flags on `shield:analyze` (CLI takes priority over auto-detected env vars, matching the `--git-branch` / `--git-commit` pattern)
- `pr_number`, `repository`, `base_branch` fields in report metadata (`POST /api/reports`) and failure notification payloads (`POST /api/reports/failure`) — only present when on a PR build or when the corresponding CLI flag is set

## v1.2.0 - 2026-03-02

### Added
- `CiEnvironmentDetector` class that auto-detects the active CI provider and resolves git branch/commit without manual configuration
- Supported providers: GitHub Actions, GitLab CI, CircleCI, Bitbucket, Azure DevOps, Jenkins, Travis CI
- Priority chain for branch and commit resolution: CLI flags (`--git-branch`, `--git-commit`) → CI platform env vars → `git` shell fallback
- `ci_provider` field in report metadata (`POST /api/reports`) and failure notification payloads (`POST /api/reports/failure`) — only present when a known CI system is detected

## v1.1.0 - 2026-03-02

### Added
- Platform failure notifications: `shield:analyze` now POSTs to `/api/reports/failure` whenever analysis exits early, so the ShieldCI dashboard can record and surface failures that never produced a report
- `AnalysisFailureReason` enum with four cases: `InvalidOptions`, `AllCategoriesDisabled`, `NoAnalyzersRan`, `UncaughtException`
- `FailureNotification` value object whose `toArray()` output mirrors the `/api/reports` shape (`laravel_version` and `package_version` are top-level fields)
- `ClientInterface::sendFailureNotification()` / `ShieldCIClient` implementation posting to `POST /api/reports/failure`
- Failure notifications are sent silently — any API error is swallowed so notifications never interrupt command flow

## v1.0.12 - 2026-02-27

### Fixed
- `AuthenticationAnalyzer` now detects custom auth middleware classes used via `->middleware(ValidateApiToken::class)` by introspecting the middleware source file for auth signals (`bearerToken()`, `AuthenticationException`, `getPassword()`, `AuthenticatesRequests`, `Auth\Factory`)
- `AuthenticationAnalyzer` no longer silently skips entire `api.php` files when sanctum/passport is mentioned — unprotected routes in mixed api.php files are now correctly flagged

### Changed
- **Breaking:** `public_routes` config now uses exact path matching instead of keyword matching — entries must be full paths starting with `/` (e.g. `'/webhooks/stripe'` instead of `'webhook'`). Default `/login` no longer matches `/auth/login`; add `/auth/login` explicitly if needed
- Default public routes updated: removed `'webhook'` and `'verify'`, added `/password/reset`, `/password/email`, `/email/verify` as exact paths
- Removed route name matching (`->name('auth.login')`) — only route URI paths are matched

## v1.0.11 - 2026-02-26

### Fixed
- `CookieSecurityAnalyzer` no longer false-positives on `env()` calls with secure defaults (e.g. `'same_site' => env('SESSION_SAME_SITE', 'lax')` was incorrectly flagged as weak SameSite protection)
- `CookieSecurityAnalyzer` now detects insecure `env()` defaults for `http_only` and `secure` checks (e.g. `env('SESSION_HTTP_ONLY', false)` was previously missed)
- `HSTSHeaderAnalyzer` now resolves `env()` defaults when detecting HTTPS-only apps and checking session cookie security (e.g. `'secure' => env('SESSION_SECURE_COOKIE', true)` is now recognised as HTTPS-only)
- Added `resolveConfigValue()` helper and `envHasDefault` flag to `InspectsCode` trait for correct `env()` default resolution in config array parsing

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
