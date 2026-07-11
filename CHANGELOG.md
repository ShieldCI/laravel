# Changelog

## v1.10.2

### Fixed
- `blade-nested-foreach` now flags only a nested `@foreach` that scans an unrelated collection to match each outer item, so iterating a group's own members, a lookup keyed by the outer item, or a relation no longer reports a bogus O(n²) finding (#276)

### Added
- `logic-in-blade` accepts a `max_foreach_depth` option (default 2) (#276)

## v1.10.1

### Fixed
- `EloquentModelDetector` now resolves an `extends` chain's parent by class name instead of collapsing the parent's whole file to a single verdict, so a class whose parent shares a file with a sibling or anonymous `class ... extends Model` is no longer detected as an Eloquent model — which produced false `MassAssignmentAnalyzer` and `FillableForeignKeyAnalyzer` findings and wrongly suppressed `ServiceContainerResolutionAnalyzer` ones (#274)

## v1.10.0

### Fixed
- `ServiceContainerResolutionAnalyzer` recognizes `MorphPivot` as an Eloquent base, so a model extending it is no longer flagged for manual container resolution — it was the only model detector in the package that omitted `MorphPivot` (#269)
- `FatModelAnalyzer` now requires a `Models` namespace segment before treating a parent whose name ends in `Model` as a custom base model, so `*ViewModel`/`*ReadModel`/`*DomainModel` subclasses are no longer analyzed as fat models; genuine bases such as `App\Models\BaseModel` and modular `Modules\*\Models` bases still count (#270)
- Model detection is now unified behind a shared `EloquentModelDetector` across the model-aware analyzers (service-container resolution, fillable foreign keys, mass assignment, fat models, mixed query builder), replacing ten divergent private checks that disagreed on several class shapes; detection now consistently recognizes models extending a project or vendor base (Spatie, Cashier, Sanctum), aliased Eloquent imports (`use Model as Eloquent`), and modular `*\Models\*` namespaces, and no longer treats a parentless class merely sitting in `App\Models` as a model (#271)

### Changed
- `EloquentModelHelper` (Eloquent mass-assignment config parsing) moved into the package under `ShieldCI\Support` from the framework-agnostic `analyzers-core`, where Laravel-specific knowledge did not belong; no behavior change (#272)

## v1.9.6

### Fixed
- `MixedQueryBuilderEloquentAnalyzer` no longer flags a read-only class that mixes `DB::table()` with Eloquent when it explicitly manages global scopes via `withoutGlobalScope()`/`withoutGlobalScopes()` and performs no query-builder writes — a deliberate cross-tenant analytics pattern where the scope bypass is intentional and signalled; query-builder writes (which bypass model events/casts) still flag, and classes that never call `withoutGlobalScope()` are unaffected (#262)
- `PhpSideFilteringAnalyzer` no longer flags `filter()`/`reject()` whose predicate reads a JSON/array-cast attribute sub-key (e.g. `$q->config['required']`) or a `data_get()`/`Arr::get()` nested lookup — these have no portable SQL equivalent (JSON path operators differ across SQLite and MySQL) so the predicate cannot be pushed into the query; mirrors the existing authorization-predicate skip, and `filter()`/`reject()` on plain columns still flag (#263)
- `EloquentNPlusOneAnalyzer` no longer flags the generate-until-unique idiom (`while (Model::where('code', $code)->exists()) { $code = ...; }`) as N+1 — an `exists()`/`doesntExist()` query in a `while`/`do-while` condition whose probed variable is reassigned in the loop body is a bounded uniqueness search, not a per-row query; queries in the loop body, non-existence terminals, and per-item existence checks inside a `foreach` still flag (#264)

## v1.9.5

### Fixed
- `MissingDatabaseTransactionsAnalyzer` no longer flags writes in a private/protected helper that is protected by a caller's `DB::transaction()` only transitively — transaction-delegation now resolves through the whole intra-class call graph, not just one hop (#260)

## v1.9.4

### Fixed
- `CookieSecurityAnalyzer`: completes the v1.9.3 `web`-group fix, which still misfired during a full `shield:analyze` run — group detection now reads the HTTP kernel's middleware groups instead of the router's, which the analyzer suite resets mid-run (#259)

## v1.9.3

### Fixed
- `CookieSecurityAnalyzer` no longer reports EncryptCookies as "not registered" when it's in the Laravel 11+ default `web` middleware group (#258)

## v1.9.2

### Fixed
- `ChunkMissingAnalyzer` now downgrades single-parent relationship-accessor reads (`$model->relation()->get()`) from a failure to a warning, since one parent's child set is far more often bounded than a table-wide `Model::`/`DB::table()` scan (#256)

## v1.9.1

### Fixed
- `EloquentNPlusOneAnalyzer` no longer flags loops of `updateOrCreate`/`firstOrCreate`/`upsert` — deliberate per-row writes rather than accidental read N+1 — nor `database/seeders`, migrations, or factories, where looping upserts is the idiomatic idempotent-seeding pattern (#252)
- `MissingDocBlockAnalyzer` no longer flags framework-contract methods (Mailable, FormRequest, queued Job/Listener, Middleware, Eloquent `Scope`, `ValidationRule`, `Responsable`, Console Command, Notification, `JsonResource`, Filament — each gated to its base class/interface so identically-named plain-class methods stay flagged), trivially self-documenting methods (single statement, or typed assignments feeding one return), or controller methods (every public method is a route action); recommendations now name only the tags a method actually needs (#253)
- `ServiceContainerResolutionAnalyzer` no longer false-positives on `app()`/container use in framework-fixed contexts it previously missed — Eloquent global `Scope` classes, model-event closures (including trait `boot{Trait}()` methods), and middleware detected by the `App\Http\Middleware` namespace or a `handle(Request, Closure)` signature — and downgrades `FormRequest::authorize()`/`rules()` to Low since method injection there is possible via `$container->call()`; bindings stay flagged at High (#254)

## v1.9.0

### Fixed
- `MassAssignmentAnalyzer` no longer crashes (an error result that wiped out all its findings) on skipped destructuring slots like `[, , $x] = ...` — whose `List_` items contain literal nulls — or on first-class-callable syntax such as `Model::create(...)`; the AST walker now guards against null nodes and non-`Arg` arguments (#247)
- `PasswordSecurityAnalyzer` no longer reports a false `missing_password_rehash` on Laravel 11+, where `Auth::attempt()` auto-rehashes via `config('hashing.rehash_on_login')` (default `true`) — an unpublished `config/hashing.php` is now treated as default-enabled. Explicit `rehash_on_login = false`, and unset config on Laravel 9/10, still flag as before (#248)
- `ChunkMissingAnalyzer` no longer flags `foreach` loops over a tiny seeded reference-catalogue table — a fixed, bounded table cannot cause the memory blow-up chunking guards against (#249)

### Added
- `SeededTableScanner` and `ModelTableResolver` (`ShieldCI\Support`) — shared helpers that identify seeder-only reference/catalogue tables and resolve a model's table (honouring explicit `$table` overrides), so analyzers can exempt bounded catalogue reads from large-dataset hints (#249)

## v1.8.8

### Fixed
- `MassAssignmentAnalyzer` and `FillableForeignKeyAnalyzer` no longer false-positive on models that declare mass-assignment config via the Laravel 12+ `#[Fillable]`/`#[Guarded]`/`#[Unguarded]` attributes (used by the official starter kits) — both now read the config from properties or attributes via `EloquentModelHelper` (#242)
- `CsrfAnalyzer` no longer reports false "missing CSRF protection" for route files `require`d inside a `->group(Closure)` — e.g. `Route::domain()->middleware('web')->group(fn () => require ...)`, the Laravel 11+ skeleton form — which `BootstrapRouteParser` previously treated as unprotected (#243)
- `LoginThrottlingAnalyzer` no longer reports false "login route lacks rate limiting" when throttling is defined in a FormRequest — it now scans `app/Http/Requests` and recognizes the starter-kit `LoginRequest::ensureIsNotRateLimited()` pattern (#244)
- `DebugLogAnalyzer` no longer pins runtime-injected log channels (e.g. `laravel-cloud-socket`, `nightwatch`) to a bogus `config/logging.php` location with an unactionable "edit config/logging.php" recommendation — it now drops the location and names the real lever (platform env var / service provider `boot()`) (#245)

## v1.8.7

### Fixed
- `OpcacheAnalyzer` no longer pins issues to commented `php.ini` lines — when a directive has no active line, the issue now carries no line/snippet instead of falling back to line 1, which made PHP defaults look like misconfigured active settings (#240)
- `OpcacheAnalyzer` `memory_consumption` check now converts the byte value from `opcache_get_configuration()` to MB before comparing — it previously compared bytes against an MB threshold and never fired (#240)

### Added
- `OpcacheAnalyzer` now scans `conf.d` drop-ins (`php_ini_scanned_files()`), pinning a directive tuned in e.g. `conf.d/10-opcache.ini` to the correct file and line (#240)

## v1.8.6

### Fixed
- `ComposerValidationAnalyzer` no longer reports a false Critical "composer.json validation failed" finding when the `composer` binary is absent (slimmed CI containers, or steps that restore `vendor/` without installing composer) — a missing binary made `composer validate` exit 127, indistinguishable from a real schema error; the subprocess is now skipped when composer cannot be run, while JSON syntax is still validated independently (#238)

## v1.8.5

### Fixed
- Suppressed High/Critical issues no longer leave a result mislabeled "failed" — when inline `@shieldci-ignore`, an `ignore_errors` rule, or a baseline match removes the last High/Critical issue and only Low/Medium issues remain, the result now downgrades to "warning" (and "passed" when all issues are suppressed); suppression only removes issues, so status can only improve. Exit codes and score are unchanged

## v1.8.4

### Fixed
- `ConfigOutsideConfigAnalyzer` no longer false-positives on long descriptive identifiers (e.g. camelCase array keys) reported as "Possible hardcoded API key or secret" — the heuristics now skip strings in identifier positions (array-access keys, array-literal keys, and `compact()` arguments) since these can never hold a credential; array values continue to be scanned (#235)

## v1.8.3

### Changed
- `FillableForeignKeyAnalyzer` now reports only curated ownership/impersonation keys (`user_id`, `owner_id`, … extensible via `dangerous_patterns`) — the generic `*_id` branch produced evidence-free false positives and is removed, and the duplicate `$guarded = []` finding is dropped in favour of `MassAssignmentAnalyzer` (#232)

### Fixed
- `MassAssignmentAnalyzer` now also analyses `Authenticatable`, `Pivot`, and `MorphPivot` models, not just `extends Model` / `App\Models` — so `$guarded = []` on a legacy `App\User` or a pivot outside `App\Models` is no longer missed (#233)

## v1.8.2

### Fixed
- `CacheHeaderAnalyzer` no longer false-positives on Laravel Vapor — Vapor serves compiled assets from a CDN with platform-managed cache headers rather than from `APP_URL`, so probing `APP_URL` is unactionable; the analyzer now skips on Vapor/serverless, mirroring the existing Laravel Cloud skip (#231)

## v1.8.1

### Fixed
- `MethodLengthAnalyzer` and `MissingDatabaseTransactionsAnalyzer` no longer false-positive on Filament 4 projects — `MethodLengthAnalyzer` now skips declarative fluent-builder methods (`form()`/`table()`/`panel()`, migration `up()`) whose length reflects configuration size rather than branching (gated behind `code-quality.method-length.ignore_fluent_chains`, default `true`) and adopts the `ClassifiesFiles` trait so it stops flagging seeders/migrations; `MissingDatabaseTransactionsAnalyzer` now scopes write counting per callback closure (so sibling `Action::make()->action(fn …)` handlers aren't summed together), attributes closure-only findings to the closure's declaration line, and ignores Filament filter `->toggle()` chains rooted at `::make()` as UI toggles rather than relationship writes (#220)
- `FilePermissionsAnalyzer` no longer flags world-readable `.env` (`644`) as Critical on developer machines — sensitive-file permission checks (world-readable, exceeds-max, group-writable) now run only in staging/production via `getEnvironment()`, consistent with `DebugModeAnalyzer`; world-writable `.env` remains Critical in every environment (#221)
- `AuthenticationAnalyzer` now honours `public_routes` config in two previously-missed cases — `isPublicRoute()` matches slash-insensitively with `fnmatch()` globs (so `/welcome/*` matches `welcome/{employee}`), and a route group is suppressed when every nested route is explicitly public instead of being flagged unconditionally (#222)
- `ServiceContainerResolutionAnalyzer` no longer false-positives where `app()` has no DI surface to migrate to — global helper functions, container-as-factory calls (`app(Class::class, [$params])`, `makeWith`), and Filament static methods (`table()`/`form()`) and action closures are now suppressed; bindings and bare `app(X::class)` in services/controllers stay flagged (#223)
- `PhpSideFilteringAnalyzer` no longer reports duplicate findings for the same `filter()` call in a longer chain (detection is now anchored to the filtering node rather than re-firing on downstream calls like `->each()`), and no longer flags `filter()`/`reject()` closures that filter by authorization checks (`$user->can(...)`, `Gate::allows()`, `hasRole()`) since these have no SQL `where`-clause equivalent (#224)
- `PasswordSecurityAnalyzer` recommendation for `missing_password_defaults` now names a service provider's `boot()` method as the canonical location (dropping the incorrect `bootstrap/app.php` suggestion for Laravel 11/12) and lists only the requirements the analyzer actually enforces (`min(>=8)`, `mixedCase()`, `uncompromised()`) rather than over-promising numbers/symbols (#225)
- `LogicInBladeAnalyzer` no longer flags published vendor templates — `getBladeFiles()` now skips any path containing `/vendor/`, so framework-authored files like `resources/views/vendor/notifications/email.blade.php` are excluded; logic in the developer's own templates is still flagged (#226)
- `shield:analyze --analyzer=X --report` / `--category=Y --report` no longer transmits a partial report to the platform as if it were a full project scan — scoped runs (detected via `isScopedRun()`) now skip the API upload with a warning, and the streaming report card is suppressed for single-analyzer runs; failure notifications and `--ci` runs are unaffected (#227)
- `MissingDocBlockAnalyzer` no longer produces documentation noise on framework-fixed methods — Filament UI classes skip `form`/`table`/`infolist`/`panel` and the `can*` authorization family, and scaffolding files (migrations, factories, seeders) are skipped entirely; suppression is class-context + method-name based so it survives Filament v3→v4 signature churn (#228)
- `ViewCachingAnalyzer` no longer false-positives with "stale view cache" findings on Laravel Vapor — the build pipeline resets Blade mtimes during packaging and the Lambda filesystem is read-only, making the mtime comparison unreliable and the `php artisan view:cache` recommendation unactionable; the analyzer now skips via `PlatformDetector::isLaravelVapor()` with a clear skip reason (#229)

## v1.8.0

### Added
- Platform integration config keys in `config/shieldci.php`: `token` (`SHIELDCI_TOKEN`), `project_id` (`SHIELDCI_PROJECT_ID`), `api_url` (`SHIELDCI_API_URL`), and `report.send_to_api` (`SHIELDCI_SEND_TO_API`) — send results to the ShieldCI dashboard via `shield:analyze --report`; the package works fully offline without credentials (#202)
- `pro_package_version` included in API payloads and JSON output when `shieldci/laravel-pro` is installed (#202)

## v1.7.26

### Fixed
- `LogicInBladeAnalyzer` no longer false-positives with "Unclosed @php block detected" on single-statement `@php($expr)` directives — the structural pass matched `@php\b` for both the block form (`@php ... @endphp`) and the self-closing parenthesised form (`@php($var = value)`), entering block-tracking mode for the latter and never finding a matching `@endphp`; single-statement directives are now detected via `@php\s*\(` and skipped before block tracking begins (#214)
- `PasswordSecurityAnalyzer` no longer false-positives on Filament `dehydrateStateUsing` closures — the closure's return value is a transformed state string for the form, not a plaintext password being stored; the analyzer now suppresses findings when the enclosing method is `dehydrateStateUsing` (#213)

## v1.7.25

### Fixed
- `shield:analyze` no longer exhausts PHP memory when pro analyzers are installed — pro analyzers create private `AstParser` instances that bypass the container, making them invisible to the existing `clearParserCache()` singleton call; `runAll()`, `run()`, and `AnalyzeCommand` now call `clearAstParserCache()` via `method_exists()` after each `analyze()` invocation

## v1.7.24

### Changed
- Recommendation strings in `ConfigCachingAnalyzer`, `SessionDriverAnalyzer`, `QueueDriverAnalyzer`, `DebugLogAnalyzer`, `AppKeyAnalyzer`, `LogicInBladeAnalyzer`, and `XssAnalyzer` tightened — internal repetition removed (clauses that restated the same point in different words), and cross-detection duplicates differentiated so each detected pattern names its specific context rather than sharing a generic category-level string

## v1.7.23

### Changed
- All recommendation strings across all 73 analyzers are now pure prose — PHP function calls (e.g. `Hash::make()`, `bcrypt()`), method chains (`->method()`), static access (`Class::method()`), PHP variable syntax (`$var`), array key-value literals (`'key' => value`), and inline code blocks have been removed; every recommendation now states the why and the what to do in plain language without embedding PHP syntax
- `DetectsLaravelVersion` trait extracted to `src/Concerns/DetectsLaravelVersion.php` — replaces duplicated `class_exists(Illuminate\Foundation\Configuration\Middleware::class)` inline checks across `AuthenticationAnalyzer`, `LoginThrottlingAnalyzer`, and `UnusedGlobalMiddlewareAnalyzer` with `version_compare(app()->version(), '11.0.0', '>=')`, which is authoritative across all environments and requires no PHPStan suppression annotations
- `AuthenticationAnalyzer` and `LoginThrottlingAnalyzer` now emit version-aware recommendations via the trait — Laravel 11+ users see guidance referencing `bootstrap/app.php`; Laravel 9/10 users see guidance referencing `app/Http/Kernel.php`

## v1.7.22

### Fixed
- `shield:analyze` no longer exhausts the PHP memory limit on large projects — `AstParser` is a singleton whose internal file cache accumulated parsed AST trees across all 73 analyzers without being cleared; `AnalyzerManager` now calls `clearParserCache()` after each `analyze()` invocation, which also eliminates false positives in `SilentFailureAnalyzer` and `MissingDatabaseTransactionsAnalyzer` caused by `resolveNames()` mutating cached `Node` objects in-place between analyzers

## v1.7.21

### Changed
- `AnalyzerManager` now instantiates each analyzer class exactly once per run — `getAnalyzers()` and `getSkippedAnalyzers()` share a cached instance pool instead of independently resolving all 73 classes; all seven `shieldci.*` config keys are read once and reused; repeated calls to either method within the same invocation return immediately from memory
- `AnalyzeCommand` now emits a warning instead of calling `set_time_limit()` on Lambda/Vapor — `set_time_limit()` is a no-op on AWS Lambda and the call was silently ignored; the warning directs users to configure the Lambda function timeout directly or use `--ci` to reduce analyzer scope
- `VulnerableDependencyAnalyzer` and `FrontendVulnerableDependencyAnalyzer` now set `$runInCI = false` — these analyzers make an external HTTP call (`api.osv.dev`) and spawn a subprocess (`npm audit`) respectively; both are excluded from `--ci` runs where dedicated pipeline steps already handle dependency scanning

## v1.7.20

### Fixed
- `MassAssignmentAnalyzer` no longer false-positives on models that inherit mass assignment protection from a parent class — subclasses of vendor models (e.g. `PersonalAccessToken extends Laravel\Sanctum\PersonalAccessToken`) were flagged as missing `$fillable`/`$guarded` because only the current class's own properties were checked; the analyzer now walks the parent class file via Composer's classmap before emitting the finding

## v1.7.19

### Fixed
- `LicenseAnalyzer` no longer flags `shieldci/*` packages — the tool's own packages ship without a public SPDX license declaration, causing the analyzer to emit missing-license or non-standard-license findings against itself

## v1.7.18

### Fixed
- `ChunkMissingAnalyzer` no longer false-positives on `DB::query()->fromSub(...)` derived-table queries — `fromSub`, `joinSub`, `leftJoinSub`, and `rightJoinSub` in the method chain now exempt the call; result bounds are encoded in the subquery structure, not a terminal method like `limit()`; plain `DB::table()->get()` continues to be flagged
- `ChunkMissingAnalyzer` no longer false-positives on queries that pass `DB::raw()` inside `select([...])` — a correlated subquery in the select list signals explicit, bounded SQL that does not need chunking

## v1.7.17

### Fixed
- `PHPStanAnalyzer` and `AnalyzeCommand` now honour `SHIELDCI_TIMEOUT` when set as an environment variable — `env()` returns strings, so `is_int('600')` was silently falling back to the default; both callsites now apply the same `is_numeric()` cast already used in `Reporter`

## v1.7.16

### Fixed
- `UpToDateDependencyAnalyzer` no longer false-positives on live Vapor Lambda deployments — Composer is not installed in Lambda containers; `shouldRun()` now returns `false` on serverless runtimes so the check is skipped entirely
- `UpToDateDependencyAnalyzer` metadata `composer_version_check` now reflects `--ignore-platform-reqs` when it is passed to the dry-run

## v1.7.15

### Fixed
- `UpToDateDependencyAnalyzer` no longer false-positives on Laravel Vapor, serverless, and Laravel Cloud — `composer.lock` is generated on the developer's machine but the dry-run executes on a different OS with different PHP extensions, causing Composer to report platform-specific packages as needing updates; `--ignore-platform-reqs` is now passed to the dry-run on these platforms so only version-constraint differences are evaluated; real outdated dependencies continue to be detected correctly

## v1.7.14

### Fixed
- `PHPStanAnalyzer` no longer times out on Laravel Vapor / AWS Lambda — `PHPStanRunner` now emits `parallel.maximumNumberOfProcesses: 1` in the generated NEON config when `PlatformDetector::isServerless()` is true; PHPStan 2.x spawns up to 32 worker processes by default and each one cold-loads PHPStan + Larastan from Lambda's read-only filesystem, exhausting memory and I/O before analysis completes; `tmpDir` is now always written to `sys_get_temp_dir() . '/phpstan'` so PHPStan's result cache does not attempt writes to the read-only `/var/task` tree; the PHPStan subprocess timeout now reads from `shieldci.timeout` (default 300 s) so it can be set below Vapor's `cli-timeout`, giving the catch block time to return a clean error result before Lambda terminates the container

## v1.7.13

### Fixed
- `XssAnalyzer` HTTP header checks (live CSP verification) now only run in production/staging — previously ran in all non-CI environments, causing false positives for developers using Docker, Valet `.test` domains, or ngrok tunnels; `analyzeHttpHeaders()` now gates on `isHttpCheckEnvironment()` consistent with `shieldci.environment_mapping` (#193)
- `EnvHttpAccessibilityAnalyzer` HTTP accessibility checks now only run in production/staging — previously ran in all non-CI environments, causing spurious Critical alerts when a local web server (Docker, Valet) serves `.env` files at a dev URL; `shouldRun()` now gates on `isHttpCheckEnvironment()` (#194)
- `HSTSHeaderAnalyzer` no longer false-positives when `URL::forceHttps(false)` is called — any `forceHttps()` call was treated as HTTPS enforcement regardless of its argument; the fix inspects the first argument and skips calls where it is a literal `false`; no-argument and variable-argument calls continue to be treated as HTTPS-only (#195)

## v1.7.12

### Fixed
- `SilentFailureAnalyzer` no longer false-positives on empty catch blocks that contain an explanatory comment — previously the comment text had to match a hardcoded keyword list; `isIntentionalIgnoreComment()` is removed and `hasExplanatoryComment()` now passes on any comment with non-empty content, treating its presence as sufficient evidence of a deliberate choice; bare `//` markers with no text continue to be flagged

## v1.7.11

### Fixed
- `CsrfAnalyzer`, `XssAnalyzer`, `FilePermissionsAnalyzer`, and `FillableForeignKeyAnalyzer` no longer embed severity as a text prefix in issue message strings (e.g. `"Critical: All routes excluded..."` → `"All routes excluded..."`) — severity is already expressed via the typed `Severity` enum on each issue and rendered separately by the output layer; embedding it again as a prefix created redundancy and risked the text label drifting out of sync with the enum value; 22 prefixes removed; `FilePermissionsAnalyzer` also renames `"Critical file"` to `"Sensitive file"` where the word described the file sensitivity tier rather than the finding's severity level — that check carries `Severity::Medium`, making `"Critical file"` a misleading mismatch (#190)
- `MissingDatabaseTransactionsAnalyzer` no longer false-positives on third-party static `::create()` calls — non-Eloquent classes that expose a factory method of the same name were incorrectly counted as database write operations; static write-method calls are now validated against Eloquent model ancestry via PHP reflection (full inheritance chain including vendor parents), an AST parent-chain registry built from project files (up to 3 levels), and namespace heuristics as a fallback (#191)

## v1.7.10

### Fixed
- `FrontendVulnerableDependencyAnalyzer` now correctly reports vulnerability titles when running against projects using npm v7+ — npm audit v2 format stores advisory details (`title`, `url`, `severity`, `range`, `cves`) inside each vulnerability's `via` array as objects rather than at the top level; the analyzer was passing the raw vulnerability object to `createFrontendVulnerabilityIssue()` which found no `title` key and fell back to "Known security vulnerability"; `parseNpmAuditResults()` now iterates `via` entries and merges each advisory object with the parent vulnerability before creating the issue, so titles such as "ip-address has XSS in Address6 HTML-emitting methods" are correctly surfaced; `via` entries that are strings (transitive dependencies — packages affected only because they depend on a vulnerable package) are no longer reported as separate issues, eliminating the duplicate "Known security vulnerability" entries for packages like `express-rate-limit` that carry no direct advisory
- `Reporter::streamResult()` now shows the individual issue message for single issues at file-only locations (no line number) — previously, issue messages were only rendered below the location line when multiple issues shared the same location; for lock files such as `package-lock.json` and `yarn.lock` the location alone ("At package-lock.json") carries no meaningful context, and the message is the only identifier of which package is affected; the condition is now `count > 1 || location->line === null`, so file:line locations (e.g. `app/Http/Controllers/Foo.php:42`) continue to display without a redundant message indent for single issues, while file-only locations always show the `→ message` line

## v1.7.9

### Fixed
- `HSTSHeaderAnalyzer` no longer false-negatives when a middleware file contains a comment referencing HSTS (e.g. `// HSTS configuration`) without actually setting the header — only the presence of `Strict-Transport-Security` in file content is treated as evidence the header is set; previously any mention of the string `HSTS` suppressed the missing-header finding
- `HSTSHeaderAnalyzer` no longer false-negatives when a security package such as `bepsvpt/secure-headers` appears only in `require-dev` — `composer.json` is now decoded and only the `require` section is checked; a dev-only package provides no HSTS protection in production

## v1.7.8

### Fixed
- `MissingDatabaseTransactionsAnalyzer` no longer false-positives on private methods exclusively called from within a `DB::transaction()` closure — the analyzer now runs a pre-scan pass over each file to identify which `$this->method()` calls occur inside transaction closures versus outside them; methods called only from within a transaction closure are treated as already protected when their writes are counted, so the "delegate pattern" (an orchestrating method that wraps all work in `DB::transaction()` by calling private helpers) no longer produces spurious findings; methods called from both inside and outside a transaction continue to be flagged as before (#186)

## v1.7.7

### Fixed
- `CacheHeaderAnalyzer` no longer runs on Laravel Cloud — Cloud manages asset cache headers at the CDN level with no configuration mechanism available to the application, making any finding unactionable; the analyzer now skips with a clear reason rather than reporting a false positive (#185)

## v1.7.6

### Fixed
- `XssDetectionAnalyzer` no longer false-positives on `style-src 'unsafe-inline'` in Content Security Policy headers — CSP directives are now parsed individually rather than matched against the full header string, so `style-src 'unsafe-inline'` is only flagged when it appears as its own directive; previously, a valid `default-src 'none'; style-src 'unsafe-inline'` policy was incorrectly passing because `'unsafe-inline'` was found anywhere in the string without checking which directive it belonged to (#183)

### Changed
- `EnvFileSecurityAnalyzer` no longer checks `.env` file permissions — `FilePermissionsAnalyzer` already owns this responsibility with a more thorough bitwise, multi-stage implementation; running both analyzers was producing two separate findings for the same problem; `EnvFileSecurityAnalyzer` continues to check for `.env` in public directories, real credentials in `.env.example`, and `.gitignore` / git-tracking hygiene (#184)

## v1.7.5

### Fixed
- `OpcacheAnalyzer` and `PHPIniAnalyzer` no longer false-positive on Laravel Cloud — Cloud only documents `memory_limit` as configurable via `ini_set()`; all OPcache sub-checks are suppressed on Cloud, and `PHPIniAnalyzer` now also suppresses its `PHP_INI_ALL` checks (`display_errors`, `log_errors`, etc.) on Cloud rather than checking them; on Docker both analyzers continue to suppress only `PHP_INI_SYSTEM` directives (controlled by the base image) while keeping `PHP_INI_ALL` checks active (#182)
- `CacheHeaderAnalyzer` no longer reports "missing Cache-Control headers" on Laravel Cloud — Cloud always applies a default `Cache-Control` header to asset responses, so the message now correctly reads "short-lived cache headers"; the finding and middleware recommendation are unchanged since long-lived caching of versioned assets is fully supported and safe given Cloud's deployment-triggered CDN purge (#182)


## v1.7.4

### Fixed
- `AuthenticationAnalyzer` no longer false-positives when `Auth::user()->`, `auth()->user()->`, or `$request->user()->` appears inside a heredoc, nowdoc, or string literal — `checkUnsafeAuthUsage()` now uses `collectStringLines()` from `analyzers-core` to build a set of 1-indexed line numbers that fall inside string literals and skips those lines before applying the three `preg_match` checks, so documentation blocks or inline string examples referencing the pattern are not reported as unsafe auth usage (#180)
- `UpToDateDependencyAnalyzer` no longer false-positives when `composer install --no-dev` was previously run — the analyzer reads `vendor/composer/installed.json` (Composer 2.x) to detect whether dev packages are installed and scopes the `composer install --dry-run` call with `--no-dev` when they are absent; all updates detected in that mode are classified as production-only, eliminating the false "Production and development dependencies are not up-to-date" warning for projects that intentionally exclude dev packages (#181)

## v1.7.3

### Fixed
- Five analyzers no longer false-positive inside Docker containers — `FilePermissionsAnalyzer` and `DirectoryWritePermissionsAnalyzer` skip entirely on Docker because file ownership is controlled by the image and host volume mounts, making `chmod` recommendations unactionable and `is_writable()` results unreliable; `MysqlSingleServerAnalyzer` skips on Docker because MySQL runs in a separate container and inter-container communication correctly uses TCP, making Unix socket recommendations inapplicable; `EnvFileSecurityAnalyzer` skips only its `checkEnvPermissions()` sub-check on Docker while continuing to check for `.env` in public directories, sensitive data in `.env.example`, and `.gitignore` hygiene; `PHPIniAnalyzer` no longer flags `allow_url_fopen`, `allow_url_include`, or `expose_php` on Docker — these are PHP_INI_SYSTEM directives set by the Docker base image and cannot be overridden at the application level, mirroring the existing Laravel Cloud suppression; `display_errors`, `log_errors`, and `ignore_repeated_errors` remain actionable and are still checked; Docker detection is added to the shared `DetectsDeploymentPlatform` trait via `isDocker()` backed by `PlatformDetector::isDocker()`, and all affected analyzers support `setDeploymentPlatform('docker')` for unit testing without a real Docker environment (#179)

## v1.7.2

### Fixed
- Seven analyzers no longer false-positive on Laravel Cloud — `EnvFileAnalyzer`, `EnvVariableAnalyzer`, `EnvFileSecurityAnalyzer`, and `EnvExampleAnalyzer` now skip entirely on Cloud because the platform writes a managed `.env` (permissions are fixed at 644 and cannot be changed by the application) and auto-injects `NIGHTWATCH_*`, `LOG_*`, and `REDIS_*` variables directly into the container rather than via `.env.example`; `DirectoryWritePermissionsAnalyzer` skips on Cloud because `php artisan storage:link` is explicitly listed as unnecessary (symlinks do not persist post-deploy); `FilePermissionsAnalyzer` removes only the `.env` entry from its paths-to-check on Cloud while continuing to check all directories; `PHPIniAnalyzer` no longer flags `allow_url_fopen`, `allow_url_include`, or `expose_php` on Cloud — these directives cannot be overridden in a Cloud container; `display_errors` and `log_errors` remain actionable and are still checked; detection uses the sole signal `LARAVEL_CLOUD=1`, which Cloud sets on all compute types (web, worker, scheduled task) (#178)

## v1.7.1

### Added
- `AnalyzeCommand` now emits a warning when `APP_ENV` is set to a non-standard value (e.g. `production-eu`) and no matching entry exists in `shieldci.environment_mapping` — prevents silent skips of environment-scoped analyzers without any developer feedback (#174)

### Fixed
- `DebugModeAnalyzer` no longer false-positives on non-standard environment names (e.g. `test`, `dev`, `qa`, `sandbox`) — the allowlist `['local', 'development', 'testing']` is replaced with a blocklist approach that only flags `APP_DEBUG=true` when `APP_ENV` is explicitly `production` or `staging`; any other name is treated as non-production (#175)

## v1.7.0

### Changed
- `MessageHelper` and `InlineSuppressionParser` moved to `analyzers-core` — callers now import from `ShieldCI\AnalyzersCore\Support`; the copies in `src/Support/` are deleted
- `InspectsCode::parseConfigArray()` delegates to `ConfigFileHelper::parseConfigArray()` in `analyzers-core` — removes ~60 lines of duplicated AST parsing logic
- `UnguardedModelsAnalyzer` replaces the inline `NodeTraverser` + `NameResolver` boilerplate with `$this->parser->resolveNames()` from `ParserInterface`

## v1.6.10

### Changed
- `Issue::$code` field removed; issue-type string identifiers (e.g. `'missing-env'`, `'http_only'`, `'phpstan'`) are now stored in `metadata['code']` — follows the `analyzers-core` update that dropped the legacy `?string $code` property; `createIssue()` and `createIssueWithSnippet()` call sites across all analyzer categories are updated accordingly; `ParsesPHPStanResults` and `ParsesPHPStanAnalysis` abstract method signatures no longer accept a `$code` parameter (#169)

### Fixed
- `ConfigCachingAnalyzer` no longer false-positives on Laravel Vapor — on Vapor, config is always cached by the platform during bootstrap regardless of `APP_ENV`, so flagging cached config in dev environments was incorrect; the analyzer now skips on serverless using the shared `DetectsDeploymentPlatform` trait (consistent with `EnvFileSecurityAnalyzer` and `EnvFileAnalyzer`) instead of a hand-rolled `$_ENV` check, enabling proper test overrides via `setDeploymentPlatform()` (#170)
- `PHPIniAnalyzer` no longer false-positives when a boolean ini setting is explicitly set to `Off` — PHP's `ini_get()` returns `''` for directives set to `Off`/`No`/`False`/`0`, which was previously reported as an ambiguous empty value; the analyzer now reads the raw text from the source ini file and classifies explicit boolean keywords correctly; genuinely empty values (e.g. `allow_url_fopen =`) still trigger the ambiguous warning; fixes false positives on Vapor/serverless where `allow_url_fopen = Off` and `expose_php = Off` are set in `/var/task/php/conf.d/php.ini` (#171)

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
