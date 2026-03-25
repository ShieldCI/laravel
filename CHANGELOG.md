# Changelog

## v1.6.9

### Fixed
- `SessionDriverAnalyzer::shouldRun()` now mirrors the `CustomErrorPageAnalyzer` pattern — adds a `statelessOverride` property and setter for clean unit testing without a real router or kernel, wraps `shouldRun()` in a `try/catch` for `ReflectionException` so unusual DI configurations gracefully default to running the analyzer instead of surfacing an unhandled exception, and aligns the skip-reason message with the shared wording used by `CustomErrorPageAnalyzer`
- `FilePermissionsAnalyzer` no longer false-positives on Laravel Vapor — `config/*.php` files are removed from the default checked-file list because AWS Lambda extracts deployment zips with execute bits set (mode `0555`), causing the bitmask check to flag them as overly permissive even though they are not writable; `.env.production` and `.env.prod` are also removed since Vapor injects environment variables directly via Lambda and these files never exist in a Vapor deployment
- `XssAnalyzer` no longer runs a live CSP header check on API-only (stateless) Laravel applications — `analyzeHttpHeaders()` now exits early when `appIsStateless()` returns `true`; `findLoginRoute()` previously fell back to the root URL and never returned `null`, so every stateless API got a false positive about a missing `Content-Security-Policy` header
- `ComposerValidationAnalyzer` no longer spawns a `composer validate` subprocess on serverless runtimes (AWS Lambda / Vapor) — the `composer` binary is absent in Lambda deployments where only the pre-built `vendor/` directory is present; JSON syntax is still validated via pure PHP (`json_decode`); the guard uses `PlatformDetector::isServerless()` rather than `isLaravelVapor()` so that Vapor projects analyzed locally or in CI (where composer is available) still run the full validation
- `PHPIniAnalyzer` no longer checks `log_errors` and `display_startup_errors` on Vapor/serverless — on Lambda, stderr is captured automatically by CloudWatch so PHP's file-based `log_errors` setting is irrelevant; `display_startup_errors` information-disclosure risk is also inapplicable since PHP startup errors go to internal logs rather than HTTP responses; `allow_url_fopen` is still checked as the SSRF risk applies regardless of platform
- `RouteCachingAnalyzer` no longer false-positives on Laravel Vapor — the Vapor CLI explicitly blocks `php artisan route:cache` during the build process because the Lambda filesystem is read-only at runtime; the analyzer now skips with a clear message when `PlatformDetector` identifies a serverless environment
- `SessionDriverAnalyzer` migrated to use the shared `AnalyzesMiddleware` trait — the previous private implementation was missing the `isVendorRoute()` filter introduced in the trait, which could produce false positives on Vapor/serverless setups where vendor packages inject web-group routes; the trait's two-pass stateless check is now the single canonical implementation
- `DirectoryWritePermissionsAnalyzer` no longer false-positives on Laravel Vapor — AWS Lambda mounts the deployment package as read-only and `is_writable()` returns `false` for `bootstrap/cache` even though Vapor overlays writable paths via `/tmp` bind mounts at runtime; the entire analyzer now skips on Vapor/serverless using `PlatformDetector`
- `EnvFileAnalyzer`, `EnvExampleAnalyzer`, `EnvVariableAnalyzer`, `EnvFileSecurityAnalyzer`, `FrontendVulnerableDependencyAnalyzer`, and `MinificationAnalyzer` now skip on Vapor/serverless — Vapor removes `.env`, `.env.example`, `webpack.mix.js`, and frontend lock files from deployments so all six analyzers that check for these files would always produce false positives on Lambda; a shared `DetectsDeploymentPlatform` trait (refactored from the inline implementation in `DirectoryWritePermissionsAnalyzer`) provides the single `isServerlessPlatform()` guard used by all affected analyzers
- `StableDependencyAnalyzer` no longer false-positives when `prefer-stable: true` is already set in `composer.json` — running `composer update --prefer-stable` dry-run when the project already opts into stable versions only surfaces available stable-to-stable upgrades, not genuine instability; the dry-run is now skipped entirely in this case; `checkComposerLock()` still validates any genuinely unstable installed versions

## v1.6.8

### Fixed
- `QueueDriverAnalyzer` no longer false-positives on the `database` queue driver in CI — `assessDatabaseDriver()` now calls `isTestingEnvironment()` before emitting the Low-severity warning, matching the guard already present in `assessSyncDriver()`; `$runInCI = false` is also added so the analyzer is skipped entirely when `--ci` is passed
- `SessionDriverAnalyzer`, `EnvExampleAnalyzer`, and `EnvVariableAnalyzer` now set `$runInCI = false` — these analyzers inspect runtime environment conditions (session driver, `.env` file presence) that are intentionally different in CI runners; they are skipped when `--ci` is passed

## v1.6.7

### Fixed
- `MissingDatabaseTransactionsAnalyzer` no longer counts writes in both branches of a plain if/else toward the transaction threshold — only `max(if_writes, else_writes)` is committed since both branches can never co-execute; guard-clause ifs with an else are also handled correctly; inner frames propagate their effective write count into the enclosing frame before being discarded
- `MissingDatabaseTransactionsAnalyzer` no longer false-positives on multi-level property chain calls (e.g. `$this->stripe->customers->update()`) — these are external service client calls, not query builder writes; `isNonDbFacadeChain` now returns `true` for chains rooted at two or more levels of property access
- `MissingDocBlockAnalyzer` no longer requires `@return` for PHP 8 union types composed entirely of concrete classes (e.g. `Response|JsonResponse`) — union types now recurse into member types and `@return` is only required when at least one member is a generic type (`array`, `mixed`, `callable`, `iterable`, `object`) that needs shape documentation; this resolves an unsolvable conflict with Laravel Pint's `no_superfluous_phpdoc_tags` rule
- `DirectoryWritePermissionsAnalyzer` no longer false-positives on API-only apps for the storage symlink check — `public/storage → storage/app/public` is web-specific infrastructure; directory write permission checks still run unconditionally
- `CustomErrorPageAnalyzer` no longer false-positives on API-only apps — `AnalyzesMiddleware::appIsStateless()` upgraded to a two-pass approach that handles three edge cases: a defined-but-unused `web` group (expanded routes no longer trigger a stateful classification), vendor-injected web routes (Vapor registers CSRF routes under `web` even in API-only apps; detected via `ReflectionClass` since `class_exists` returns `false` for interfaces), and `getGlobalMiddleware()` now prefers the public `Kernel::getGlobalMiddleware()` method before falling back to reflection
- `EnvFileSecurityAnalyzer` no longer flags Stripe test keys and sandbox tokens in `.env.example` as accidentally committed secrets — `sk_test_`, `pk_test_`, `rk_test_`, `whsec_test_`, `sandbox`, and `test_` prefixes are added to `$placeholderKeywords`; these tokens are designed to be shareable and cannot access production resources
- `FrontendVulnerableDependencyAnalyzer` no longer false-positives with a "No lock file found" warning on projects with an empty `package.json` — the analyzer now checks for at least one declared dependency before running
- `CsrfAnalyzer` broad `routes/*/api.php` filename heuristic replaced with AST-based `RouteServiceProvider` provider-dir scanning — `BootstrapRouteParser` now scans all `app/Providers/*.php` files using the same `Route::middleware()->group(base_path())` chain-walking logic used for `bootstrap/app.php`; all returned paths go through `realpath()` for consistent cross-platform path comparison
- `LoginThrottlingAnalyzer` path comparison now applies `realpath()` normalization — `BootstrapRouteParser` returns resolved paths consistently, preventing `in_array` mismatches on macOS where `/tmp → /private/tmp`

## v1.6.6

### Fixed
- `CsrfAnalyzer::getRouteFiles()` now delegates to `getPhpFiles()` instead of a hand-rolled `DirectoryIterator` — configured `excludePatterns` are respected and route files in subdirectories (e.g. `routes/api/`) are now picked up
- `HorizonSuggestionAnalyzerTest` — added `assertNotNull($this->app)` guards before `basePath()` calls to resolve PHPStan Level 9 `Application|null` errors

## v1.6.5

### Added
- Laravel 13 support — `illuminate/*` constraints widened to `^9.0|^10.0|^11.0|^12.0|^13.0`; `orchestra/testbench` widened to `^7.0|^8.0|^9.0|^10.0|^11.0`; CI matrix now tests PHP 8.2–8.4 against Laravel 12 and 13

## v1.6.4

### Fixed
- `configuration` field no longer arrives as `[]` in API payloads and JSON output — `AnalysisReport` is a `readonly` value object that is reconstructed at four sites in `AnalyzeCommand` (the `suppressedIssues` inject in `handle()`, `filterAgainstIgnoreErrors()`, `filterAgainstInlineSuppressions()`, and `filterAgainstBaseline()`); each site was omitting `configuration:`, causing it to silently default to `[]`; all four sites now forward `configuration: $report->configuration`

## v1.6.3

### Changed
- `MissingDatabaseTransactionsAnalyzer`, `MixedQueryBuilderEloquentAnalyzer`, `PhpSideFilteringAnalyzer`, `SilentFailureAnalyzer`, and `ServiceContainerResolutionAnalyzer` now include code snippets in their issues — each issue shows the offending line with surrounding context via `createIssueWithSnippet()`

## v1.6.2

### Added
- `shield:analyze --format=json` now shows a progress bar on STDERR while analyzers run — the bar displays the current analyzer name and advances per-analyzer; it only renders when STDERR is a TTY so piped or redirected STDERR stays clean

### Changed
- All status messages (e.g. "Running all 73 analyzers...") are now written to STDERR instead of STDOUT — `--format=json` output piped to `jq` or redirected to a file is no longer corrupted by interleaved text
- `--output` now suppresses STDOUT — when a file path is provided (via `--output` or `shieldci.report.output_file` config), the report is written to the file only and a `"Report saved to: ..."` confirmation is shown; the full report is no longer also dumped to the console

## v1.6.1

### Fixed
- Suppressed issues note no longer has a blank line between it and the analyzer status line — the note is now embedded directly into the streamed output so it appears immediately below the status with no gap

## v1.6.0

### Added
- JSON output and API payload now include a top-level `configuration` key capturing the effective analysis configuration at the time of the run; values reflect runtime mutations (e.g. `--ci` toggling `ci_mode`) so the snapshot always represents what was actually used, not the static config file
- Suppressed issues are now tracked and included in JSON output and API payloads — when an issue is suppressed via `@shieldci-ignore` inline comment, `ignore_errors` config rule, or `--baseline`, it appears in a `suppressed_issues` array inside the corresponding analyzer result with full detail (message, location, severity, recommendation) plus a `suppression` block identifying the type (`inline`, `config`, or `baseline`) and the specific rule that matched; the top-level `summary` now includes a `suppressed_issues` breakdown by type; console output shows a brief count hint per analyzer when issues were suppressed (e.g. "Passed (2 issues suppressed)")

## v1.5.19

### Fixed
- `shield:analyze --analyzer=<id>` no longer errors with "Analyzer(s) not found" when the requested analyzer exists but is skipped (e.g. `runInCI = false` with `--ci`, or environment-conditional analyzers like `HSTSHeaderAnalyzer`) — `validateOptions()` now distinguishes between truly unknown IDs (error) and skipped IDs (yellow warning); skipped results are included in the output and streamed correctly in both streaming and non-streaming paths; the "Running analyzer: X" header now resolves the analyzer's display name from skipped metadata instead of falling back to the raw ID

## v1.5.18

### Fixed
- Dependency analyzers no longer attach code snippets or line numbers to issues pointing at lock files (`composer.lock`, `package-lock.json`, `yarn.lock`) — lock files are machine-generated and not user-editable; line 1 of `composer.lock` is the `_readme` metadata header, and any line is a fragment of deeply-nested JSON with no actionable context; `code` is now `null` and `Location` carries no line number for lock file issues across `StableDependencyAnalyzer`, `UpToDateDependencyAnalyzer`, `VulnerableDependencyAnalyzer`, `LicenseAnalyzer`, and `FrontendVulnerableDependencyAnalyzer`; `composer.json` snippets are unchanged (flat structure, one key per line, readable)

## v1.5.17

### Fixed
- `NamingConventionAnalyzer` no longer checks the string value of `protected $table` for plural snake_case — a developer who explicitly sets `$table` is intentionally overriding Laravel's default (DB prefix, legacy schema, multi-tenancy, etc.) and the analyzer must not second-guess that choice; PSR naming conventions govern PHP identifiers, not string literals; the property name `table` is valid camelCase and is the only check that applies

## v1.5.16

### Changed
- Score now excludes skipped analyzers from the denominator — `score()` in `AnalysisReport`, per-category percentages in `Reporter::generateReportCard()`, and per-category percentages in `AnalyzeCommand::outputReportCard()` all use `total - skipped` as the denominator; a project where all applicable checks pass now scores 100% in CI regardless of how many analyzers were skipped due to `runInCI = false`
- Report card: "Not Applicable" row moved to the last position and percentage columns removed — the row is purely informational context, not a scored metric

## v1.5.15

### Fixed
- `Reporter::hyperlink()` no longer wraps URLs in OSC 8 terminal escape sequences in CI environments and unsupported terminals — log viewers that don't implement OSC 8 were consuming the display text as part of the control sequence, rendering the documentation URL invisible; `hyperlink()` now falls back to plain text when `CI` is set or when no known capable terminal (`TERM_PROGRAM`, `VTE_VERSION`, `WT_SESSION`) is detected

### Changed
- `EnvFileSecurityAnalyzer` now sets `runInCI = false` — the analyzer checks for the presence and permissions of `.env` files, which are intentionally absent in CI runners that inject secrets via environment variables rather than files; skipped when `--ci` is passed

## v1.5.14

### Changed
- `EnvFileAnalyzer`, `FilePermissionsAnalyzer`, `CachePrefixAnalyzer`, and `DirectoryWritePermissionsAnalyzer` now set `runInCI = false` — these analyzers check conditions that depend on CI runner environment setup (`.env` presence/permissions, filesystem permission bits, shared cache server prefix, storage symlinks) rather than developer-controlled code, so they are not meaningful in CI and are skipped when `--ci` is passed

## v1.5.13

### Fixed
- `MixedQueryBuilderEloquentAnalyzer` now reports the Query Builder call line for mixed Eloquent/QB issues instead of the Eloquent call line — the QB call is the actual offending statement and is the correct anchor for inline suppression and code navigation
- `ServiceContainerResolutionAnalyzer` no longer false-positives on Eloquent models (instantiated via `newInstance()`/`new static()`; constructor DI is impractical), `ShouldQueue` classes (the serialization lifecycle bypasses `__construct`; `app()` in `via()` is canonical), and service providers (all resolution inside service providers is suppressed — `boot()` and its private helpers are bootstrap infrastructure); issue locations now use relative paths via `getRelativePath()` consistent with all other analyzers
- `SilentFailureAnalyzer` no longer emits Low severity issues for broad catches (`Throwable`/`Exception`/`Error`) that both log the exception and reference the exception variable — these are well-handled patterns (e.g. `Log::error() + markAsFailed($e->getMessage())` in jobs and controllers); High severity (no logging) and Medium severity (logging but `$e` unused) are retained

## v1.5.12

### Fixed
- `MissingDatabaseTransactionsAnalyzer` no longer false-positives on guard clause patterns — an `if`-block with no `else`/`elseif` whose last statement is `return` or `throw` is now recognised as a guard clause; writes inside it are isolated (they exist on execution paths that always terminate before reaching the main flow) and are excluded from the atomicity threshold check; fixes false positives like a guard clause deleting a record before a properly-wrapped `DB::transaction()`

## v1.5.11

### Added
- `EloquentNPlusOneAnalyzer` upgraded to registry-based detection with semantic type inference — a two-pass architecture scans all model files first (`EloquentModelRelationshipScanner`) to build relationship, attribute, and accessor registries, then uses precise registry lookups during N+1 traversal; unknown variable types no longer produce false positives
- Column-constrained eager loads (`with('project:id,uuid,name')`) are now correctly matched — the colon suffix is stripped before relationship name comparison

### Fixed
- `FatModelAnalyzer` no longer reports a line number for class-level issues (method count, LOC) — these are whole-class concerns with no single causal line; complexity issues retain their method start line as before
- `HelperFunctionAbuseAnalyzer` now counts unique helper functions per class instead of total calls — a class calling `config()` seven times has one implicit dependency (the config system), not seven; thresholds recalibrated for unique-count scale (High at ≥ 10 distinct helpers, Medium at ≥ 5)
- `LogicInBladeAnalyzer` no longer false-positives on `@props` and `@aware` Blade component directives — these compile to framework-internal PHP containing `array_filter` (for `ComponentSlot` detection), which was incorrectly flagged as "business logic found in Blade directive"

## v1.5.10

### Fixed
- `ChunkMissingAnalyzer` no longer false-positives when a variable name used in a `foreach` in one method matches a query-assigned variable from a different method in the same class — `$variableAssignments` is now reset on entry to each `ClassMethod`, `Function_`, `Closure`, and `ArrowFunction` scope
- `ChunkMissingAnalyzer` no longer false-positives on `->pluck(...)->all()` chains — `pluck()` executes the query and returns an in-memory `Collection`; the subsequent `->all()` is `Collection::all()` (array conversion), not `Builder::all()`, and is now correctly treated as safe

## v1.5.9

### Added
- `InlineSuppressionParser` now recognises `@shieldci-ignore` inside multi-line docblocks — when the line immediately above a flagged issue ends with the block-comment closing marker, the parser scans backward through the block for a matching suppression tag; this covers both standalone suppress docblocks and `@shieldci-ignore` placed inside an existing `@param`/`@return` docblock

## v1.5.8

### Fixed
- `CustomErrorPageAnalyzer` recommendation now lists only the templates that are actually missing instead of always enumerating all 7 — if a project already has `404.blade.php`, it will no longer appear in the recommendation text

### Changed
- `CustomErrorPageAnalyzer` reads the required template list from `shieldci.analyzers.reliability.custom-error-pages.required_templates` config (falling back to the default 7 templates) — advanced users can override this list without modifying the published config file

## v1.5.7

### Fixed
- `UnusedGlobalMiddlewareAnalyzer` no longer false-positives on `TrustProxies` and `TrustHosts` in Laravel 11+ applications — in Laravel 11+, these are framework-level defaults injected by `Illuminate\Foundation\Configuration\Middleware`, not user-registered middleware, so flagging them as "unused" was incorrect for every Laravel 11+ app
- `UnusedGlobalMiddlewareAnalyzer` now reports issues against `bootstrap/app.php` on Laravel 11+ (instead of the non-existent `app/Http/Kernel.php`), and the `HandleCors` recommendation text now references `withMiddleware()` in `bootstrap/app.php` on Laravel 11+
- Laravel version detection uses `class_exists(Illuminate\Foundation\Configuration\Middleware::class)` — reliable across all environments (no filesystem dependency)

## v1.5.6

### Fixed
- `LoginThrottlingAnalyzer` no longer false-positives on route files registered with a throttle middleware directly on their group in `bootstrap/app.php` (e.g. `Route::prefix('api/v1')->middleware(['api', 'throttle:api.rest'])->group(base_path('routes/api-v1.php'))`) — these files now correctly inherit their rate-limiting protection and are skipped
- `LoginThrottlingAnalyzer` no longer false-positives on `GET /token/verify` and similar token management endpoints in `routes/api.php` — `token`/`oauth` URL keywords now only trigger a check on `POST`, `any`, and `match` routes (credential submission methods); `GET`, `resource`, and `controller` routes only match the `login`/`signin`/`auth`/`authenticate` keywords

### Added
- `BootstrapRouteParser::getThrottleProtectedRouteFiles()` — detects route files registered with any `throttle:*` middleware (string or array form) on their group in `bootstrap/app.php`; used by `LoginThrottlingAnalyzer` to suppress false positives on externally throttled route groups

## v1.5.5

### Fixed
- `CsrfAnalyzer` no longer false-positives on API route files (e.g. `routes/api-v1.php`) registered under the `api` middleware group via `withRouting(then: ...)` in `bootstrap/app.php` — these files use Sanctum token-based authentication and must not have `web` middleware; they are now correctly skipped
- `BootstrapRouteParser::chainContainsMiddleware` now recognises array-form middleware declarations (e.g. `->middleware(['api', 'throttle:api.rest'])`) in addition to the string form `->middleware('api')`

### Added
- `BootstrapRouteParser::getApiRegisteredRouteFiles()` — detects route files registered under the `api` middleware group through two sources: `require`/`include` statements in `routes/api.php`, and `Route::middleware('api'|['api', ...])->...->group(base_path(...))` chains in `bootstrap/app.php`

## v1.5.4

### Fixed
- `FillableForeignKeyAnalyzer` now reports each issue at the specific `$fillable` array item line (e.g. `'user_id',`) instead of the `protected $fillable = [` declaration line — fixes `@shieldci-ignore` comments placed on the offending entry being silently ignored
- `NamingConventionAnalyzer` now reports property violations at the individual property line (`$prop->getStartLine()`) and constant violations at the individual constant line (`$const->getStartLine()`) instead of the parent statement line — same inline-suppression fix applies
- `PasswordSecurityAnalyzer` now reports weak `password_hash()` option issues (`bcrypt cost`, `argon2 memory_cost`, `time_cost`, `threads`) at the offending array item line instead of the `password_hash(` call line

## v1.5.3

### Fixed
- `CsrfAnalyzer` no longer false-positives on route files registered with `web` middleware externally via `withRouting(then: ...)` in `bootstrap/app.php` (e.g. `Route::middleware('web')->group(base_path('routes/auth.php'))`) — these files inherit CSRF protection from the middleware group and are now correctly skipped
- `LoginThrottlingAnalyzer` no longer false-positives on login routes in the same externally-registered route files — throttle applied globally to the `web` group is now respected

### Added
- `BootstrapRouteParser` support class (`ShieldCI\Support`) — AST-based utility that detects route files covered by the `web` middleware group through external registration; checks both `require`/`include` statements in `routes/web.php` and `Route::middleware('web')->...->group(base_path(...))` chains in `bootstrap/app.php`; used by `CsrfAnalyzer` and `LoginThrottlingAnalyzer`

## v1.5.2

### Fixed
- `AuthenticationAnalyzer` now correctly recognises custom auth middleware classes applied at the group level via `Route::middleware(ClassName::class)->group()` — the class name was previously unresolved due to a NameResolver timing issue in single-pass traversal
- `AuthenticationAnalyzer` now correctly inherits middleware from multi-segment route chains such as `Route::prefix('api')->middleware('auth')->group()` — intermediate method calls between the `Route::` static call and `->group()` are now walked correctly
- `AuthenticationAnalyzer` now correctly maps legacy string-format route handlers (`'Controller@method'`, `'Controller'`) to controller methods for auth-stat tracking

### Changed
- `AuthenticationAnalyzer` route file analysis fully migrated from regex/line-based parsing to PHP-Parser AST via a new `RouteAuthVisitor` — 17 regex methods removed; all valid PHP formatting variants (multiline chains, different indentation, etc.) are now handled without fragility

## v1.5.1

### Fixed
- `AuthenticationAnalyzer` no longer false-positives on invokable controllers registered on plain `Route::get()` routes (e.g. `PrivacyController`, `LandingController`) — unauthenticated GET routes now mark the target method as intentionally public, consistent with named resource actions `index`/`show`; POST/PUT/PATCH/DELETE routes without auth middleware continue to be flagged
- `AuthenticationAnalyzer` no longer false-positives on `FormRequest::authorize() => true` when the `FormRequest` is injected into an auth-gated controller action (route middleware, constructor middleware, or `middleware()` method) — only unprotected sensitive actions are flagged; orphaned `FormRequest` classes are also skipped
- `AuthenticationAnalyzer` no longer false-positives on `Auth::user()->`, `auth()->user()->`, or `$request->user()->` calls inside controller methods that are verifiably protected by auth middleware — suppression uses the already-computed `routeAuthStats` and `publicControllerMethods` maps (route-level) or constructor / `middleware()` method inspection (controller-level)

## v1.5.0

### Added
- `--category` now accepts comma-separated values to run multiple categories in one pass (e.g. `--category=security,performance`)
- `AnalyzerManager::getByCategories(array $categories)` — filters the registered analyzer pool to any number of categories at once
- Warning emitted when both `--analyzer` and `--category` are provided simultaneously (`--category` is silently ignored in that case; the warning makes the precedence explicit)

### Changed
- `--category` help text updated to document comma-separated usage

## v1.4.0

### Added
- `--ci` flag on `shield:analyze` — activates CI mode directly from the command line without any environment variable or config file change

### Changed
- CI mode is now activated exclusively via `--ci` on `shield:analyze` (and the existing `--ci` on `shield:baseline`); the `SHIELDCI_CI_MODE` env var path is removed

### Removed
- `ci_mode` key from `config/shieldci.php` — the `SHIELDCI_CI_MODE` environment variable is no longer read; use `--ci` instead (`ci_mode_analyzers` and `ci_mode_exclude_analyzers` remain unchanged)

## v1.3.0

### Added
- `CiEnvironmentDetector::resolvePrNumber()` — auto-detects the pull-request / merge-request number from CI env vars across all 7 supported providers; GitHub falls back from `GITHUB_REF_NUMBER` to parsing `refs/pull/N/` from `GITHUB_REF`
- `CiEnvironmentDetector::resolveRepository()` — resolves `owner/repo` from CI env vars (GitHub, GitLab, CircleCI, Bitbucket, Travis CI; Azure DevOps and Jenkins are skipped — their vars don't reliably produce this format)
- `CiEnvironmentDetector::resolveBaseBranch()` — resolves the PR target branch from CI env vars; absent on non-PR builds
- `--git-pr-number`, `--git-repository`, `--git-base-branch` CLI flags on `shield:analyze` (CLI takes priority over auto-detected env vars, matching the `--git-branch` / `--git-commit` pattern)
- `pr_number`, `repository`, `base_branch` fields in report metadata (`POST /api/reports`) and failure notification payloads (`POST /api/reports/failure`) — only present when on a PR build or when the corresponding CLI flag is set

## v1.2.0

### Added
- `CiEnvironmentDetector` class that auto-detects the active CI provider and resolves git branch/commit without manual configuration
- Supported providers: GitHub Actions, GitLab CI, CircleCI, Bitbucket, Azure DevOps, Jenkins, Travis CI
- Priority chain for branch and commit resolution: CLI flags (`--git-branch`, `--git-commit`) → CI platform env vars → `git` shell fallback
- `ci_provider` field in report metadata (`POST /api/reports`) and failure notification payloads (`POST /api/reports/failure`) — only present when a known CI system is detected

## v1.1.0

### Added
- Platform failure notifications: `shield:analyze` now POSTs to `/api/reports/failure` whenever analysis exits early, so the ShieldCI dashboard can record and surface failures that never produced a report
- `AnalysisFailureReason` enum with four cases: `InvalidOptions`, `AllCategoriesDisabled`, `NoAnalyzersRan`, `UncaughtException`
- `FailureNotification` value object whose `toArray()` output mirrors the `/api/reports` shape (`laravel_version` and `package_version` are top-level fields)
- `ClientInterface::sendFailureNotification()` / `ShieldCIClient` implementation posting to `POST /api/reports/failure`
- Failure notifications are sent silently — any API error is swallowed so notifications never interrupt command flow

## v1.0.12

### Fixed
- `AuthenticationAnalyzer` now detects custom auth middleware classes used via `->middleware(ValidateApiToken::class)` by introspecting the middleware source file for auth signals (`bearerToken()`, `AuthenticationException`, `getPassword()`, `AuthenticatesRequests`, `Auth\Factory`)
- `AuthenticationAnalyzer` no longer silently skips entire `api.php` files when sanctum/passport is mentioned — unprotected routes in mixed api.php files are now correctly flagged

### Changed
- **Breaking:** `public_routes` config now uses exact path matching instead of keyword matching — entries must be full paths starting with `/` (e.g. `'/webhooks/stripe'` instead of `'webhook'`). Default `/login` no longer matches `/auth/login`; add `/auth/login` explicitly if needed
- Default public routes updated: removed `'webhook'` and `'verify'`, added `/password/reset`, `/password/email`, `/email/verify` as exact paths
- Removed route name matching (`->name('auth.login')`) — only route URI paths are matched

## v1.0.11

### Fixed
- `CookieSecurityAnalyzer` no longer false-positives on `env()` calls with secure defaults (e.g. `'same_site' => env('SESSION_SAME_SITE', 'lax')` was incorrectly flagged as weak SameSite protection)
- `CookieSecurityAnalyzer` now detects insecure `env()` defaults for `http_only` and `secure` checks (e.g. `env('SESSION_HTTP_ONLY', false)` was previously missed)
- `HSTSHeaderAnalyzer` now resolves `env()` defaults when detecting HTTPS-only apps and checking session cookie security (e.g. `'secure' => env('SESSION_SECURE_COOKIE', true)` is now recognised as HTTPS-only)
- Added `resolveConfigValue()` helper and `envHasDefault` flag to `InspectsCode` trait for correct `env()` default resolution in config array parsing

## v1.0.10

### Fixed
- `AuthenticationAnalyzer` no longer false-positives on nested public route URIs (e.g. `/auth/login`, `/api/v1/register`) — the public-route regex now allows path segments before the keyword
- `AuthenticationAnalyzer` no longer false-positives on dotted public route names (e.g. `auth.login`, `admin.auth.register`) — the route-name regex now allows dotted prefixes
- Recommendation text now mentions the `public_routes` config option as an alternative to `->middleware("guest")`

## v1.0.9

### Fixed
- `SqlInjectionAnalyzer` no longer false-positives on table/column name concatenation in `*Raw()` fragment methods (e.g. `->orderByRaw('(col/' . $table . '.goal) ASC')`) — only direct user input sources (`$_GET`, `$_POST`, `request()`, `Request::input()`) are flagged (#97)
- `SqlInjectionAnalyzer` no longer false-positives on structural concatenation in `DB::select/insert/update/delete` when bindings are present (e.g. `DB::select('...IN (' . $placeholders . ')', $bindings)`) — the presence of bindings indicates parameterized query awareness (#97)

## v1.0.8

### Fixed
- `MassAssignmentAnalyzer` recommendations no longer suggest `request()->validated()` as a universal alternative — clarified that `validated()` requires a `FormRequest` subclass, with `request()->only([...])` as the universal safe option (#96)

## v1.0.7

### Fixed
- `HSTSHeaderAnalyzer` no longer false-positives on multi-line header definitions (e.g. `$response->headers->set(\n  'Strict-Transport-Security',\n  'max-age=31536000; includeSubDomains'\n)`) — now gathers a context window across subsequent lines (#95)
- `includeSubDomains` and `preload` directive checks are now case-insensitive per RFC 6797

## v1.0.6

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

## v1.0.5

### Fixed
- `XssAnalyzer` no longer flags literal-output ternaries inside `<script>` tags as JavaScript XSS (e.g. `{{ $coll->contains(request()->route()->getName()) ? 'true' : 'false' }}`) — both branches are string/boolean/numeric/null literals so the output can never contain user-controlled data

## v1.0.4

### Fixed
- Remove `preload` from HSTS missing-header recommendation to match default config (`require_preload => false`) and avoid encouraging an irreversible browser preload list submission

## v1.0.3

### Fixed
- `AuthenticationAnalyzer` now recognises `Route::middleware('guest')->group()` wrappers so routes inside guest groups are no longer false-positived as "missing auth middleware"
- Route groups using array syntax (`Route::group(['middleware' => 'guest', ...])`) are also recognised
- Controller methods pointed to by routes in guest groups are correctly marked as intentionally public
- Improved recommendation strings to mention `->middleware("guest")` as a valid alternative for intentionally public routes

## v1.0.2

### Fixed
- Fix "Documentation URL:" never appearing in console output by using `getDocsUrl()` accessor instead of raw `docsUrl` property in `AnalyzeCommand`

## v1.0.1

### Fixed
- Widen `larastan/larastan` from `^2.0` to `^2.0|^3.0` and `phpstan/phpstan` from `^1.10` to `^1.10|^2.0` to fix installation on Laravel 12 projects (#89)

## v1.0.0

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
