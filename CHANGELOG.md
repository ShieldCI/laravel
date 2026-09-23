# Changelog

## v1.16.0

### Added
- `OriginReachabilityChecker` probes each origin the app declares once and names the outcome, so an unreachable host cannot read as a clean result (#404)

### Changed
- `env-http-accessibility` verifies TLS certificates on its probes, so a staging origin with a self-signed certificate warns rather than passing (#408)
- Requires `shieldci/analyzers-core ^2.6` (was `^2.5`), for the shared AST parser every analyzer now resolves through (#412)

### Fixed
- `logic-in-blade` and `eloquent-n-plus-one` analyze Blade views containing a multi-line directive, an inline `@php`, a `@switch` or a raw `<?php` tag, rather than skipping them and reporting a pass (#407, #409, #413, #414, #416)
- `logic-in-blade` no longer reports `blade-unclosed-php-block` for a `@php` that is not a directive, such as one written in prose or inside `{{-- --}}` (#414)
- `logic-in-blade` no longer reports `blade-inline-php` for a `<?php` occurring inside a `@php` block body, such as one in a string or heredoc (#416)
- `env-http-accessibility` warns when a location produced no response, instead of reporting the web server properly configured from zero replies (#408)

## v1.15.3

### Changed
- Requires `shieldci/analyzers-core ^2.5` (was `^2.3`), so a failed analyzer's stack trace no longer records each frame's arguments (#398)

### Fixed
- `method-length` no longer loses a method's declarative exemption to a leading assignment or a trailing comment (#394)
- `method-length` exempts up to 15 declarative statements rather than 5, so six `RateLimiter::for()` blocks are no longer flagged (#394)
- An analyzer that catches its own failure truncates and redacts the message, so `database-status` no longer reports a raw PDO error (#401)

## v1.15.2

### Fixed
- `phpstan` and `collection-call-optimization` run on projects that require a newer PHP than the `php` first on `PATH`, instead of aborting with "PHPStan produced no analysable output" (#390)

## v1.15.1

### Fixed
- `logic-in-blade`, `csrf-protection` and `xss-vulnerabilities` honour `excluded_paths` when scanning Blade views and JavaScript files (#385)
- `unused-global-middleware` and `cookie` name the middleware file the project actually has, `app/Http/Kernel.php` or `bootstrap/app.php`, instead of choosing by Laravel version or naming a file that is not there (#387)
- `phpstan` and `collection-call-optimization` run on projects whose `phpstan.neon` or `phpstan/extension-installer` already loads Larastan, instead of aborting with "This file is included multiple times" (#388)

## v1.15.0

### Added
- `report.snippet_plain_mode` and `report.snippet_syntax_highlighting` now govern a real code preview rendered under each console finding (#380)

### Changed
- `fat-model`, `nesting-depth`, `method-length`, `helper-function-abuse` and `env-example-documented` warn instead of failing a default `fail_on: high` build, and `authentication-authorization` reports an unprotected route as Critical, after every analyzer's severity metadata was audited against the findings it emits (#347)
- `php-side-filtering` reports High rather than Critical, since Critical is reserved for security exposure, data loss, or an app that cannot serve requests (#349)
- `shield:analyze` exits 1 when an analyzer could not complete; add the analyzer id to `dont_report` in `config/shieldci.php` to waive one (#351)
- Requires `guzzlehttp/guzzle ^7.0|^8.0` (was `^7.0`), so installing on a Laravel 13 app no longer fails or downgrades the app's guzzle (#359)
- A malformed config value is now a suppressible finding rather than an analysis error, and a missing prerequisite reports skipped, across `cache-driver`, `queue-driver`, `session-driver`, `mysql-single-server-optimization`, `view-caching`, `config-caching`, `collection-call-optimization` and `phpstan` (#362)
- Requires `shieldci/analyzers-core ^2.3` (was `^2.1`) for the config-location helpers the unpublished-config fixes now resolve through (#373)

### Fixed
- `logic-in-blade` flags `file_get_contents()` as an API call only when the argument spells out a remote target, so `{!! file_get_contents(public_path('img/logo.svg')) !!}` is no longer reported (#341)
- `phpstan` reports an error instead of a clean pass when a run does not finish, such as an internal error or a configured path that does not exist (#342)
- `collection-call-optimization` works in an installed package at all: its shipped config included Larastan by a path resolving inside `vendor/shieldci/laravel/vendor`, so PHPStan aborted and the analyzer reported a pass on every real install (#345)
- `phpstan` no longer reports the Larastan 2.9.0 env-call finding twice, once under Other PHPStan Issues and once through `env-call-outside-config` (#350)
- `phpstan` no longer reads the unmatched ignore patterns in a project's own `phpstan.neon` as an analysis that did not complete (#354)
- `cache-driver` assesses the driver when `config/cache.php` has not been published, instead of erroring out on a stock Laravel 11+ skeleton (#356)
- Eight analyzers omit the issue location when the config file they report on is not published, rather than pointing into a file merged from the framework or fabricating line 1 (#361)
- The exit-code gate now sees a failure that names no issue, waives `dont_report` analyzers under `fail_threshold`, and falls back to the documented default on an unrecognised `fail_on` (#363)
- `shield:baseline` no longer waives an analyzer that could not run by writing it into the baseline's `dont_report`, and names the analyzers the baseline does not cover (#365)
- A failed analyzer's exception class and stack trace survive into the JSON report, and `timeToFix` reaches `--format=json` (#366)
- `shieldci.report.format` and `SHIELDCI_REPORT_FORMAT` take effect: `--format` declared a default of its own, so the config fallback behind it was unreachable (#370)
- `shield:analyze` writes no ANSI escapes to a piped or redirected run, and honours `--no-ansi`, `NO_COLOR` and `FORCE_COLOR` throughout rather than for a handful of messages (#372)
- `shield:analyze --format=json` keeps advisories such as a baseline notice or an unmapped `APP_ENV` on stderr, so the report on stdout stays parseable (#374)
- `--output` writes to the path it validated, resolved against `base_path()`, and always as JSON rather than console art (#379)
- An empty or missing `shieldci.paths.analyze` falls back to the shipped paths, instead of leaving 108 file analyzers scanning nothing and reporting a pass (#382)

## v1.14.0

### Added
- `EloquentModelDetector`: `verdictForClassName()`/`isModelClassName()` resolve a class reference through the referencing file's imports (#326)
- `eloquent-n-plus-one` answers conclusively once a model's whole chain is read, so plain columns like `sku` are no longer flagged (#334)

### Fixed
- `logic-in-blade` exempts paginator window views, wherever they live, from the move-to-controller checks (#327)
- `logic-in-blade` nested-`@foreach` now matches a linear search on the inner loop's key, not only its value (#329)
- `eloquent-n-plus-one` treats snake_case property access as a column, so `*_type` columns are no longer flagged (#331)
- `eloquent-n-plus-one` resolves relationships from traits and parents, so `$user->notifications` on `Notifiable` is no longer flagged (#333)
- `phpstan` gives each error one category, ending duplicate findings and inflated counts; unmatched errors go to a new `other` category (#337)
- `service-container-resolution` handles php-parser 5.9's `ArgPlaceholder`, restoring container-call detection (#338)

## v1.13.3

### Fixed
- `xss-vulnerabilities` no longer flags a single-line `<script>` tag's own HTML attributes (such as a CSP nonce) as JavaScript-context injection (#324)

## v1.13.2

### Fixed
- `env-example-documented` no longer flags bare `env()` keys read in vendor-named config files such as `services.php` (#322)

## v1.13.1

### Fixed
- `env-example-documented` now requires a `.env.example` entry only for config `env()` keys without a default (#320)

## v1.13.0

### Added
- `env-example-documented` now also reports an `env()` key read by the app's own `config/` files but absent from `.env.example`, per key at the config file and line; keys shipped by installed packages' vendor configs and stock Laravel skeleton keys are exempt, and an `ignored_keys` option (wildcards allowed) covers the rest (#318)
- `env-variables-complete` gains opt-in `report_defaulted` and `report_redundant` options (default off) that report config-defaulted absences and `.env` values restating a config default as Info issues (#317)

### Fixed
- `env-variables-complete` no longer flags a variable missing from `.env` when its `env()` call in `config/` supplies a real default, so a lean `.env` holding only overrides and secrets passes; a bare `env('KEY')` or explicit `null` default still reports High (#317)

## v1.12.6

### Fixed
- `public_routes` now composes route-group prefixes into the full URI before matching the allowlist, so a prefixed nested route is no longer flagged as unprotected (#305)
- `authentication-authorization` now resolves string middleware aliases (e.g. `['device.token']`) to their class via an alias map from `bootstrap/app.php` and `app/Http/Kernel.php`, so a route guarded by a custom alias is no longer flagged as missing authentication; `auth.basic` is recognised too (#312)
- `vulnerable-dependencies` now hydrates each OSV advisory (`GET /v1/vulns/{id}`) for its real title, CVE, and affected ranges, matches comma-separated ranges as AND, and fails open when a range can't be resolved (#313)
- `login-throttling` no longer flags Sanctum-style APIs: it recognises `$middleware->throttleApi()` as global throttling, detects fluent/array throttled route groups via AST line ranges, and skips non-credential endpoints like `auth/logout`, `auth/me`, and `auth/signout` (#314)
- `service-container-resolution` no longer flags container access inside `addGlobalScope()`, `addGlobalScopes()`, or `resolveRelationUsing()` closures, which Eloquent invokes in a DI-impossible context like the already-exempt model-event closures; service bindings stay flagged (#315)

## v1.12.5

### Changed
- `shieldci.memory_limit` acts as a floor, so it no longer lowers a higher ambient limit such as Vapor's runtime default or an unlimited CLI (#302)

### Fixed
- `shield:analyze` no longer exhausts the PHP memory limit on a multi-megabyte codebase, where an analyzer type-hinting the concrete parser received a private instance whose cache was never cleared between analyzers (#302)
- Analyzers that built a parser per file, as `xss-vulnerabilities` did, reuse the shared one, removing redundant re-parsing and unmanaged caches (#303)

## v1.12.4

### Fixed
- `eloquent-n-plus-one` no longer flags a loop-dependent query whose chain takes a pessimistic row lock, such as `StoreItem::lockForUpdate()->whereKey($id)->firstOrFail()` inside a `foreach` (#297)
- `eloquent-n-plus-one` no longer flags a loop-dependent query followed by an unconditional `return` or `throw`, or a `break` when a single loop encloses it, since it runs at most once per call (#298)
- `mass-assignment-vulnerabilities` no longer flags an `update()`, `create()` or `fill()` argument that is an array literal whose keys are all string literals, such as `$entry->update(['days' => $collection->all()])` (#299)
- `php-side-filtering` no longer flags an argument-less `filter()` or `reject()` after an Eloquent fetch, which has no predicate to push into a `WHERE` clause (#300)

## v1.12.3

### Fixed
- `shieldci.memory_limit` reaches the PHPStan subprocess through `--memory-limit`, so analyzing a large project no longer exhausts the ambient limit while PHPStan builds its trees (#295)

## v1.12.2

### Fixed
- `fillable-foreign-key` no longer flags a model that declares no local `$fillable` or `$guarded` or builds `$fillable` dynamically, so one inheriting its mass-assignment configuration from a parent, including a vendor base the AST cannot follow into, is not reported (#293)

## v1.12.1

### Fixed
- `app-key-security` no longer reports a valid base64 `APP_KEY` containing `//` as malformed (#291)

## v1.12.0

### Changed
- Requires `shieldci/analyzers-core ^2.1` (was `^1.5`), which fixes a `TypeError` raised when `shieldci.environment_mapping` maps an environment to a non-string value (#282)

## v1.11.0

### Added
- `eloquent-n-plus-one` analyzes Blade templates, carrying each variable's model type and eager-loaded relations over from the controller that renders the view, so a relation lazily accessed inside a `@foreach` is reported on the Blade line and names the controller to eager-load it in (#279)

### Fixed
- `eloquent-n-plus-one` no longer reports an accessor on a model that defines no relationships, so reading `$user->full_name` inside a loop is not flagged (#279)

## v1.10.2

### Added
- `logic-in-blade` accepts a `max_foreach_depth` option, default 2 (#276)

### Fixed
- `blade-nested-foreach` flags only a nested `@foreach` that scans an unrelated collection to match each outer item, so iterating a group's own members, a lookup keyed by the outer item, or a relation no longer reports a bogus quadratic finding (#276)

## v1.10.1

### Fixed
- `EloquentModelDetector` resolves an `extends` chain by parent class name rather than collapsing the parent's whole file to one verdict, so a class whose parent shares a file with an anonymous `class ... extends Model` is no longer read as a model (#274)
- `mass-assignment-vulnerabilities` and `fillable-foreign-key` therefore stop reporting that class, and `service-container-resolution` stops being wrongly suppressed on it (#274)

## v1.10.0

### Changed
- `EloquentModelHelper`, which parses Eloquent mass-assignment configuration, moved into this package under `ShieldCI\Support` from the framework-agnostic `analyzers-core`, where Laravel-specific knowledge did not belong; behaviour is unchanged (#272)

### Fixed
- Model detection is unified behind a shared `EloquentModelDetector` across the model-aware analyzers, replacing ten private checks that disagreed on several class shapes (#271)
- Detection recognises a model extending a project or vendor base, an aliased Eloquent import and a modular `*\Models\*` namespace, and no longer treats a parentless class merely sitting in `App\Models` as a model (#271)
- `service-container-resolution` recognises `MorphPivot` as an Eloquent base, so a model extending it is no longer flagged for manual container resolution; it was the only detector in the package omitting it (#269)
- `fat-model` requires a `Models` namespace segment before treating a parent whose name ends in `Model` as a custom base, so a `*ViewModel` or `*ReadModel` subclass is no longer analysed as a fat model; a genuine base such as `App\Models\BaseModel` still counts (#270)

## v1.9.6

### Fixed
- `mixed-query-builder-eloquent` no longer flags a read-only class mixing `DB::table()` with Eloquent when it manages global scopes explicitly through `withoutGlobalScope()` and performs no query-builder writes, a deliberate cross-tenant pattern where the bypass is signalled; writes still flag (#262)
- `php-side-filtering` no longer flags a `filter()` or `reject()` predicate reading a JSON or array-cast sub-key, or a `data_get()` lookup, which have no portable SQL equivalent and so cannot be pushed into the query; a predicate on a plain column still flags (#263)
- `eloquent-n-plus-one` no longer flags the generate-until-unique idiom, an `exists()` query in a `while` condition whose probed variable is reassigned in the body being a bounded search rather than a per-row query (#264)

## v1.9.5

### Fixed
- `missing-database-transactions` resolves transaction delegation through the whole intra-class call graph rather than one hop, so a private helper protected by a caller's `DB::transaction()` only transitively is no longer flagged (#260)

## v1.9.4

### Fixed
- `cookie` reads middleware groups from the HTTP kernel rather than the router, completing the v1.9.3 fix, which still misfired during a full `shield:analyze` run because the analyzer suite resets the router mid-run (#259)

## v1.9.3

### Fixed
- `cookie` no longer reports `EncryptCookies` as unregistered when it sits in the Laravel 11+ default `web` middleware group (#258)

## v1.9.2

### Fixed
- `chunk-missing` reports a single-parent relationship read such as `$model->relation()->get()` as a warning rather than a failure, one parent's child set being far more often bounded than a table-wide scan (#256)

## v1.9.1

### Fixed
- `eloquent-n-plus-one` no longer flags a loop of `updateOrCreate`, `firstOrCreate` or `upsert`, which are deliberate per-row writes rather than an accidental read, nor seeders, migrations and factories, where looping upserts is the idiomatic pattern (#252)
- `missing-docblock` no longer flags a framework-contract method such as a Mailable, FormRequest, Middleware or Console Command override, each gated to its own base class so an identically named plain method is still flagged (#253)
- `missing-docblock` also skips a trivially self-documenting method and any controller method, every public one being a route action, and recommends only the tags a method actually needs (#253)
- `service-container-resolution` no longer flags container use in a framework-fixed context it had missed, namely an Eloquent `Scope` class, a model-event closure and middleware, and reports `FormRequest::authorize()` and `rules()` as Low, method injection being possible there; a binding stays High (#254)

## v1.9.0

### Added
- `SeededTableScanner` and `ModelTableResolver` (`ShieldCI\Support`) identify seeder-only reference tables and resolve a model's table, honouring an explicit `$table`, so an analyzer can exempt a bounded catalogue read from a large-dataset hint (#249)

### Fixed
- `mass-assignment-vulnerabilities` no longer errors out and loses every finding on a skipped destructuring slot such as `[, , $x] = ...`, whose list items are literal nulls, or on first-class callable syntax such as `Model::create(...)` (#247)
- `password-security` no longer reports a missing password rehash on Laravel 11+, where `Auth::attempt()` rehashes automatically and an unpublished `config/hashing.php` means enabled; an explicit `rehash_on_login = false`, and unset config on Laravel 9 and 10, still flag (#248)
- `chunk-missing` no longer flags a `foreach` over a small seeded reference table, which cannot cause the memory growth chunking guards against (#249)

## v1.8.8

### Fixed
- `mass-assignment-vulnerabilities` and `fillable-foreign-key` read mass-assignment configuration from the Laravel 12+ `#[Fillable]`, `#[Guarded]` and `#[Unguarded]` attributes used by the official starter kits, not only from properties (#242)
- `csrf-protection` no longer reports missing protection for a route file required inside a `->group(Closure)`, the Laravel 11+ skeleton form (#243)
- `login-throttling` no longer reports a missing rate limit when throttling lives in a FormRequest, recognising the starter-kit `LoginRequest::ensureIsNotRateLimited()` pattern (#244)
- `debug-log-level` drops the location and names the real lever, a platform environment variable or a service provider, for a runtime-injected log channel rather than pinning it to a `config/logging.php` line that does not describe it (#245)

## v1.8.7

### Added
- `opcache-enabled` scans `conf.d` drop-ins, pinning a directive tuned in a file such as `conf.d/10-opcache.ini` to that file and line (#240)

### Fixed
- `opcache-enabled` reports no line rather than falling back to line 1 when a directive has no active `php.ini` entry, which had made PHP defaults look like misconfigured active settings (#240)
- `opcache-enabled` converts `memory_consumption` to megabytes before comparing it against the threshold, having compared bytes against a megabyte value and so never fired (#240)

## v1.8.6

### Fixed
- `composer-validation` no longer reports a Critical validation failure when the `composer` binary is absent, as in a slimmed CI container, where `composer validate` exited 127 indistinguishably from a real schema error; JSON syntax is still validated (#238)

## v1.8.5

### Fixed
- A result no longer reads "failed" when suppression removed its last High or Critical issue: it downgrades to warning, or to passed when every issue was suppressed. Exit codes and score are unchanged (#236)

## v1.8.4

### Fixed
- `config-outside-config` no longer reports a long descriptive identifier as a possible hardcoded secret, skipping strings in identifier positions such as an array key or a `compact()` argument, which can never hold a credential; array values are still scanned (#235)

## v1.8.3

### Changed
- `fillable-foreign-key` reports only curated ownership and impersonation keys such as `user_id` and `owner_id`, extensible through `dangerous_patterns`; the generic `*_id` branch produced evidence-free findings and is removed, and the duplicate `$guarded = []` finding is left to `mass-assignment-vulnerabilities` (#232)

### Fixed
- `mass-assignment-vulnerabilities` also analyses `Authenticatable`, `Pivot` and `MorphPivot` models, so `$guarded = []` on a legacy `App\User` or a pivot outside `App\Models` is no longer missed (#233)

## v1.8.2

### Fixed
- `asset-cache-headers` skips on Laravel Vapor, which serves compiled assets from a CDN with platform-managed headers rather than from `APP_URL`, mirroring the existing Laravel Cloud skip (#231)

## v1.8.1

### Fixed
- `method-length` no longer flags a Filament 4 project, skipping a declarative fluent-builder method such as `form()` or `table()`, whose length reflects configuration rather than branching (#220)
- `missing-database-transactions` counts writes per callback closure, so sibling Filament action handlers are no longer summed together (#220)
- `file-permissions` reports a world-readable `.env` only in staging and production, so mode 644 on a developer machine is no longer Critical; a world-writable `.env` stays Critical everywhere (#221)
- `authentication-authorization` matches `public_routes` slash-insensitively with glob patterns, so `/welcome/*` covers `welcome/{employee}`, and suppresses a route group whose every nested route is explicitly public (#222)
- `service-container-resolution` no longer flags `app()` where no dependency injection is available to migrate to, such as a global helper function, a container-as-factory call or a Filament action closure; a binding is still flagged (#223)
- `php-side-filtering` reports one finding per `filter()` call rather than re-firing on downstream calls such as `->each()`, and no longer flags a closure filtering by an authorization check, which has no SQL equivalent (#224)
- `password-security` names a service provider's `boot()` method for `missing_password_defaults`, dropping the wrong `bootstrap/app.php` suggestion, and lists only the requirements it actually enforces (#225)
- `logic-in-blade` skips any path containing `/vendor/`, so a published vendor template is no longer flagged; the developer's own templates still are (#226)
- `shield:analyze --analyzer=X --report` and `--category=Y --report` skip the API upload with a warning rather than transmitting a partial scan as a full one; failure notifications and `--ci` runs are unaffected (#227)
- `missing-docblock` skips a Filament UI method and the `can*` authorization family, and skips migrations, factories and seeders entirely (#228)
- `view-caching` skips on Laravel Vapor, whose build resets Blade modification times and whose filesystem is read-only, making the comparison unreliable and `php artisan view:cache` unactionable (#229)

## v1.8.0

### Added
- Platform integration keys in `config/shieldci.php`: `token`, `project_id`, `api_url` and `report.send_to_api`, each with a `SHIELDCI_*` environment variable, send results to the ShieldCI dashboard through `shield:analyze --report`; the package still works fully offline without credentials (#202)
- API payloads and JSON output carry `pro_package_version` when `shieldci/laravel-pro` is installed (#202)

## v1.7.26

### Fixed
- `logic-in-blade` no longer reports "Unclosed @php block detected" for the single-statement form `@php($var = value)`, which it had treated as opening a block that no `@endphp` would ever close (#214)
- `password-security` no longer flags a Filament `dehydrateStateUsing` closure, whose return value is transformed form state rather than a plaintext password being stored (#213)

## v1.7.25

### Fixed
- `shield:analyze` no longer exhausts PHP memory when the pro analyzers are installed, which create private parsers the container cannot see and the existing cache clear therefore missed

## v1.7.24

### Changed
- Recommendations in `config-caching`, `session-driver`, `queue-driver`, `debug-log-level`, `app-key-security`, `logic-in-blade` and `xss-vulnerabilities` drop clauses that restated the same point, and each detected pattern now names its own context rather than sharing one category-level string

## v1.7.23

### Changed
- Every recommendation across the 73 analyzers is plain prose, with PHP syntax such as `Hash::make()`, `->method()`, `$var` and inline code removed, so each states why and what to do without embedding code
- `authentication-authorization` and `login-throttling` give version-aware recommendations, naming `bootstrap/app.php` on Laravel 11+ and `app/Http/Kernel.php` on Laravel 9 and 10

## v1.7.22

### Fixed
- `shield:analyze` no longer exhausts the PHP memory limit on a large project: the shared parser accumulated every file parsed across all 73 analyzers, and its cache is now cleared after each one
- Clearing that cache also removes false positives in `silent-failure` and `missing-database-transactions`, caused by name resolution mutating a cached tree between analyzers

## v1.7.21

### Changed
- `vulnerable-dependencies` and `frontend-vulnerable-dependencies` set `runInCI = false`, one calling an external API and the other spawning `npm audit`, work a pipeline usually has its own step for
- `shield:analyze` warns rather than calling `set_time_limit()` on Lambda, where the call is silently ignored, and points at the function timeout or `--ci` instead
- `AnalyzerManager` instantiates each analyzer once per run, sharing one pool between `getAnalyzers()` and `getSkippedAnalyzers()` rather than resolving all 73 classes twice

## v1.7.20

### Fixed
- `mass-assignment-vulnerabilities` no longer flags a model inheriting mass-assignment protection from a parent, such as one extending `Laravel\Sanctum\PersonalAccessToken`, walking the parent class through Composer's classmap before reporting

## v1.7.19

### Fixed
- `license-compliance` no longer flags `shieldci/*` packages, which ship without a public SPDX declaration and so reported the tool against itself

## v1.7.18

### Fixed
- `chunk-missing` no longer flags a derived-table query using `fromSub`, `joinSub`, `leftJoinSub` or `rightJoinSub`, whose bounds live in the subquery rather than a terminal method such as `limit()`; a plain `DB::table()->get()` is still flagged
- `chunk-missing` no longer flags a query passing `DB::raw()` inside `select([...])`, a correlated subquery in the select list signalling deliberate, bounded SQL

## v1.7.17

### Fixed
- `phpstan` and `shield:analyze` honour `SHIELDCI_TIMEOUT` set as an environment variable, where `env()` returns a string and the integer check silently fell back to the default

## v1.7.16

### Fixed
- `up-to-date-dependencies` skips on serverless runtimes, where Composer is not installed in the Lambda container
- `up-to-date-dependencies` reports `composer_version_check` metadata that reflects `--ignore-platform-reqs` when the dry run used it

## v1.7.15

### Fixed
- `up-to-date-dependencies` passes `--ignore-platform-reqs` on Vapor, serverless and Laravel Cloud, where the dry run executes on a different OS than the one that wrote `composer.lock` and so reported platform-specific packages as needing updates; genuinely outdated dependencies are still found

## v1.7.14

### Fixed
- `phpstan` no longer times out on AWS Lambda: the generated config limits PHPStan to one process, where 32 workers each cold-loading from a read-only filesystem exhausted memory first, writes `tmpDir` to the system temp directory, and takes its subprocess timeout from `shieldci.timeout` so it can be set below Vapor's own

## v1.7.13

### Fixed
- `xss-vulnerabilities` runs its live CSP check only in production and staging, which had produced false positives for developers on Docker, Valet or an ngrok tunnel (#193)
- `env-http-accessibility` runs only in production and staging, which had raised spurious Critical alerts where a local web server serves `.env` at a development URL (#194)
- `hsts-header` reads the argument to `forceHttps()`, so a literal `URL::forceHttps(false)` no longer counts as HTTPS enforcement; a call with no argument or a variable one still does (#195)

## v1.7.12

### Fixed
- `silent-failure` no longer flags an empty catch block carrying an explanatory comment of any wording, the comment's presence being evidence of a deliberate choice; a bare `//` with no text is still flagged

## v1.7.11

### Fixed
- `csrf-protection`, `xss-vulnerabilities`, `file-permissions` and `fillable-foreign-key` no longer prefix an issue message with its severity, as in "Critical: All routes excluded", which duplicated what the output layer already renders and could drift from it; 22 prefixes are removed (#190)
- `file-permissions` renames "Critical file" to "Sensitive file", that check carrying Medium, so the wording no longer contradicts the severity (#190)
- `missing-database-transactions` no longer counts a third-party static `::create()` as a database write, validating the class against Eloquent ancestry by reflection and an AST parent chain rather than the method name alone (#191)

## v1.7.10

### Fixed
- `frontend-vulnerable-dependencies` reports a real advisory title such as "ip-address has XSS in Address6 HTML-emitting methods" on npm 7+, whose audit format moves the details into each vulnerability's `via` array, where the analyzer had found no title and fallen back to "Known security vulnerability"
- `frontend-vulnerable-dependencies` no longer reports a transitive `via` entry as its own issue, which had duplicated findings for packages carrying no advisory of their own
- `Reporter` shows the issue message for a single finding at a file-only location, such as one in `package-lock.json`, where the location alone names no package

## v1.7.9

### Fixed
- `hsts-header` treats only a real `Strict-Transport-Security` header as evidence the header is set, so a comment merely mentioning HSTS no longer suppresses the finding (#187)
- `hsts-header` reads only the `require` section of `composer.json`, so a security package such as `bepsvpt/secure-headers` present only in `require-dev` no longer counts as production protection (#187)

## v1.7.8

### Fixed
- `missing-database-transactions` no longer flags a private method called only from inside a `DB::transaction()` closure, so the delegate pattern of an orchestrating method wrapping private helpers is read correctly; a method called from both inside and outside a transaction is still flagged (#186)

## v1.7.7

### Fixed
- `asset-cache-headers` skips on Laravel Cloud, which manages asset cache headers at the CDN with no lever available to the application (#185)

## v1.7.6

### Changed
- `env-file` no longer checks `.env` permissions, which `file-permissions` already owns with a more thorough implementation, so one problem stopped producing two findings; it still checks for `.env` in public directories, real credentials in `.env.example` and git hygiene (#184)

### Fixed
- `xss-vulnerabilities` parses Content-Security-Policy directives individually, so `style-src 'unsafe-inline'` is flagged only in its own directive and a sound policy such as `default-src 'none'; style-src 'unsafe-inline'` no longer passes by matching the string anywhere in the header (#183)

## v1.7.5

### Fixed
- `opcache-enabled` and `php-ini` no longer report unactionable findings on Laravel Cloud, which documents only `memory_limit` as settable; on Docker both still check the directives an application can change (#182)
- `asset-cache-headers` reports short-lived cache headers rather than missing ones on Laravel Cloud, which always applies a default `Cache-Control` to asset responses; the recommendation is unchanged, long-lived caching of versioned assets being safe given Cloud's deploy-triggered purge (#182)

## v1.7.4

### Fixed
- `authentication-authorization` no longer reports unsafe auth usage for `Auth::user()`, `auth()->user()` or `$request->user()` written inside a heredoc, nowdoc or string literal, such as a documentation block quoting the pattern (#180)
- `up-to-date-dependencies` no longer reports "Production and development dependencies are not up-to-date" for a project installed with `--no-dev`, reading `vendor/composer/installed.json` to scope the dry run and classify what it finds as production-only (#181)

## v1.7.3

### Fixed
- `file-permissions` and `directory-write-permissions` skip on Docker, where the image and host volume mounts own file ownership, making a `chmod` recommendation unactionable (#179)
- `mysql-single-server-optimization` skips on Docker, where MySQL runs in its own container and TCP is the correct transport rather than a Unix socket (#179)
- `env-file` skips only its permission check on Docker and still looks for `.env` in public directories and in git (#179)
- `php-ini` stops flagging `allow_url_fopen`, `allow_url_include` and `expose_php` on Docker, which the base image sets; `display_errors`, `log_errors` and `ignore_repeated_errors` are still checked (#179)

## v1.7.2

### Fixed
- `env-file-exists`, `env-variables-complete`, `env-file` and `env-example-documented` skip on Laravel Cloud, which writes a managed `.env` at fixed permissions and injects its own variables into the container (#178)
- `directory-write-permissions` skips on Laravel Cloud, which lists `php artisan storage:link` as unnecessary because symlinks do not survive a deploy (#178)
- `file-permissions` drops only its `.env` entry on Laravel Cloud and still checks every directory (#178)
- `php-ini` stops flagging `allow_url_fopen`, `allow_url_include` and `expose_php` on Laravel Cloud, which a container cannot override; `display_errors` and `log_errors` are still checked (#178)

## v1.7.1

### Added
- `shield:analyze` warns when `APP_ENV` holds a non-standard value such as `production-eu` that `shieldci.environment_mapping` does not cover, rather than silently skipping every environment-scoped analyzer (#174)

### Fixed
- `debug-mode` flags `APP_DEBUG=true` only when `APP_ENV` is `production` or `staging`, so a name such as `dev`, `qa` or `sandbox` is treated as non-production rather than unrecognised (#175)

## v1.7.0

### Changed
- `MessageHelper` and `InlineSuppressionParser` moved to `analyzers-core`, so callers import them from `ShieldCI\AnalyzersCore\Support` and the copies under `src/Support/` are gone

## v1.6.10

### Changed
- `Issue::$code` is removed and the issue-type identifier, such as `'missing-env'` or `'phpstan'`, now lives in `metadata['code']`, following the `analyzers-core` change that dropped the property (#169)

### Fixed
- `config-caching` no longer flags cached config on Laravel Vapor, where the platform caches during bootstrap whatever `APP_ENV` says (#170)
- `php-ini` reads a boolean directive set to `Off` as explicitly disabled rather than ambiguously empty, `ini_get()` returning `''` for both; a genuinely empty value such as `allow_url_fopen =` still warns (#171)

## v1.6.9

### Fixed
- `file-permissions` no longer flags `config/*.php` on Laravel Vapor, where Lambda extracts the deployment zip with execute bits set although the files are not writable; `.env.production` and `.env.prod` are dropped from the list too, never existing on Vapor
- `xss-vulnerabilities` runs no live CSP header check on an API-only app, which previously always reported a missing `Content-Security-Policy` because the login-route lookup fell back to the root URL
- `composer-validation` spawns no `composer validate` subprocess on a serverless runtime, where the binary is absent; JSON syntax is still validated in pure PHP, and a Vapor project analyzed locally or in CI still runs the full check
- `php-ini` checks neither `log_errors` nor `display_startup_errors` on serverless, where CloudWatch captures stderr and startup errors never reach an HTTP response; `allow_url_fopen` is still checked
- `route-caching` no longer flags Laravel Vapor, whose CLI blocks `php artisan route:cache` because the Lambda filesystem is read-only at runtime
- `session-driver` adopts the shared `AnalyzesMiddleware` trait, gaining the vendor-route filter it lacked, which had produced false positives where a vendor package injects web-group routes
- `session-driver` defaults to running rather than surfacing an unhandled exception when an unusual container configuration makes reflection fail
- `directory-write-permissions` no longer flags Laravel Vapor, where `bootstrap/cache` reads as unwritable although Vapor overlays writable paths from `/tmp` at runtime
- `env-file-exists`, `env-example-documented`, `env-variables-complete`, `env-file`, `frontend-vulnerable-dependencies` and `asset-minification` skip on serverless, where Vapor strips `.env`, `.env.example`, `webpack.mix.js` and frontend lock files from the deployment
- `stable-dependencies` runs no `--prefer-stable` dry run when `composer.json` already sets `prefer-stable`, where it surfaced ordinary upgrades rather than instability; the lock file is still checked for genuinely unstable versions

## v1.6.8

### Fixed
- `queue-driver` no longer warns about the `database` driver in a testing environment, matching the guard the `sync` driver check already had, and sets `runInCI = false`
- `session-driver`, `env-example-documented` and `env-variables-complete` set `runInCI = false`, since each reads a runtime condition that CI runners deliberately differ on

## v1.6.7

### Fixed
- `missing-database-transactions` counts only the larger branch of a plain if/else toward the threshold, since both branches can never run together
- `missing-database-transactions` no longer flags a multi-level property chain such as `$this->stripe->customers->update()`, which calls an external service client rather than the query builder
- `missing-docblock` requires `@return` on a PHP 8 union type only when a member is generic, such as `array` or `mixed`, so a union of concrete classes like `Response|JsonResponse` no longer conflicts with Pint's `no_superfluous_phpdoc_tags`
- `directory-write-permissions` no longer reports a missing storage symlink on an API-only app, that link being web-specific; write permission checks still run everywhere
- `custom-error-pages` no longer flags an API-only app, since the stateless check now reads a defined-but-unused `web` group and vendor-injected web routes correctly
- `env-file` no longer reports a Stripe test key or sandbox token in `.env.example` as a committed secret, those tokens being shareable by design
- `frontend-vulnerable-dependencies` no longer warns "No lock file found" for a project whose `package.json` declares no dependencies
- `csrf-protection` finds API route files by scanning `app/Providers/*.php` for route-group registrations rather than guessing from a `routes/*/api.php` filename
- `login-throttling` resolves paths through `realpath()` before comparing them, which had mismatched on macOS where `/tmp` resolves to `/private/tmp`

## v1.6.6

### Fixed
- `csrf-protection` finds route files through `getPhpFiles()`, so configured exclude patterns are respected and a route file in a subdirectory such as `routes/api/` is picked up

## v1.6.5

### Added
- Laravel 13 support: `illuminate/*` widened to `^9.0|^10.0|^11.0|^12.0|^13.0` and `orchestra/testbench` to `^7.0|^8.0|^9.0|^10.0|^11.0`, with CI covering Laravel 10 on PHP 8.1 to 8.3, Laravel 11 on 8.2 to 8.4, Laravel 12 on 8.2 to 8.5 and Laravel 13 on 8.3 to 8.5

## v1.6.4

### Fixed
- The `configuration` field reaches API payloads and JSON output with its real contents rather than `[]`, which four reconstructions of the readonly `AnalysisReport` in `AnalyzeCommand` had been dropping

## v1.6.3

### Changed
- `missing-database-transactions`, `mixed-query-builder-eloquent`, `php-side-filtering`, `silent-failure` and `service-container-resolution` show the offending line with surrounding context on each issue

## v1.6.2

### Added
- `shield:analyze --format=json` shows a progress bar on stderr naming the running analyzer, rendered only when stderr is a TTY so a piped run stays clean

### Changed
- Status messages go to stderr rather than stdout, so `--format=json` piped to `jq` is no longer corrupted by interleaved text
- `--output` suppresses stdout, writing the report to the file and printing only a confirmation, rather than also dumping the report to the console

## v1.6.1

### Fixed
- The suppressed-issues note sits directly under its analyzer status line rather than a blank line below it

## v1.6.0

### Added
- JSON output and the API payload carry a top-level `configuration` key holding the configuration the run actually used, including runtime changes such as `--ci` turning on `ci_mode`
- A suppressed issue is now reported rather than silently dropped, appearing in a `suppressed_issues` array on its analyzer result with full detail and a block naming its type, `inline`, `config` or `baseline`, and the rule that matched
- The run summary breaks suppressed counts down by type, and the console notes them per analyzer, as in "Passed (2 issues suppressed)"

## v1.5.19

### Fixed
- `shield:analyze --analyzer=<id>` no longer errors with "Analyzer(s) not found" when the named analyzer exists but was skipped, whether for `runInCI = false` under `--ci` or an environment condition as in `hsts-header`; an unknown id still errors, a skipped one warns and appears in the output under its display name

## v1.5.18

### Fixed
- `stable-dependencies`, `up-to-date-dependencies`, `vulnerable-dependencies`, `license-compliance` and `frontend-vulnerable-dependencies` attach no code snippet or line number to an issue pointing at `composer.lock`, `package-lock.json` or `yarn.lock`, which are generated rather than hand-edited; `composer.json` snippets are unchanged

## v1.5.17

### Fixed
- `naming-convention` no longer checks the string value of `protected $table` for plural snake_case, since a developer setting it explicitly is overriding Laravel's default on purpose and PSR conventions govern identifiers rather than string literals

## v1.5.16

### Changed
- Score excludes skipped analyzers from the denominator, so a project whose applicable checks all pass scores 100% in CI however many analyzers `runInCI = false` skipped
- The report card moves its "Not Applicable" row last and drops its percentage columns, the row being context rather than a scored metric

## v1.5.15

### Changed
- `env-file` sets `runInCI = false`, since it checks for `.env` files that CI runners intentionally omit in favour of injected environment variables

### Fixed
- `Reporter::hyperlink()` writes plain text instead of an OSC 8 escape sequence when `CI` is set or no capable terminal is detected, since a log viewer that does not implement OSC 8 swallowed the URL and rendered it invisible

## v1.5.14

### Changed
- `env-file-exists`, `file-permissions`, `cache-prefix-configuration` and `directory-write-permissions` set `runInCI = false`, since each reads a condition the CI runner's setup dictates rather than the developer's code

## v1.5.13

### Fixed
- `mixed-query-builder-eloquent` reports the query builder line rather than the Eloquent one, since the query builder call is the offending statement and the right anchor for inline suppression
- `service-container-resolution` no longer flags an Eloquent model, a `ShouldQueue` class or a service provider, where constructor injection is impractical or the serialization lifecycle bypasses `__construct`; issue locations now use relative paths like every other analyzer
- `silent-failure` no longer reports Low for a broad catch that both logs the exception and uses the exception variable; High for no logging and Medium for an unused variable are unchanged

## v1.5.12

### Fixed
- `missing-database-transactions` no longer flags a guard clause, an `if` with no `else` ending in `return` or `throw`, since its writes sit on a path that always terminates before the main flow and cannot break atomicity with it

## v1.5.11

### Added
- `eloquent-n-plus-one` detects through a registry rather than guesswork: `EloquentModelRelationshipScanner` scans every model first to build relationship, attribute and accessor registries, which a second pass looks up, so an unknown variable type no longer produces a false positive
- `eloquent-n-plus-one` matches a column-constrained eager load such as `with('project:id,uuid,name')`, stripping the colon suffix before comparing relationship names

### Fixed
- `fat-model` reports no line number for a class-level issue such as method count or lines of code, which no single line causes; a complexity issue keeps its method start line
- `helper-function-abuse` counts distinct helper functions per class rather than total calls, so a class calling `config()` seven times carries one implicit dependency rather than seven; thresholds are rescaled to High at 10 distinct helpers and Medium at 5
- `logic-in-blade` no longer flags the `@props` and `@aware` component directives, which compile to framework-internal PHP containing `array_filter`

## v1.5.10

### Fixed
- `chunk-missing` no longer flags a `foreach` whose variable name happens to match a query-assigned variable in a different method of the same class, since assignments now reset on entry to each method, function and closure
- `chunk-missing` no longer flags a `->pluck(...)->all()` chain, where `all()` converts an in-memory `Collection` to an array rather than fetching every row

## v1.5.9

### Added
- `InlineSuppressionParser` recognises `@shieldci-ignore` inside a multi-line docblock, scanning back through the block when the line above a finding closes one, so the tag works in a standalone docblock or alongside existing `@param` and `@return` tags

## v1.5.8

### Changed
- `custom-error-pages` reads its required template list from `shieldci.analyzers.reliability.custom-error-pages.required_templates`, falling back to the default seven, so the list can be overridden without editing the published config

### Fixed
- `custom-error-pages` recommends only the templates actually missing, so a project that already has `404.blade.php` no longer sees it listed

## v1.5.7

### Fixed
- `unused-global-middleware` no longer flags `TrustProxies` and `TrustHosts` on Laravel 11+, where the framework injects them as defaults rather than the developer registering them
- `unused-global-middleware` reports against `bootstrap/app.php` on Laravel 11+ rather than the `app/Http/Kernel.php` that does not exist there, and its `HandleCors` recommendation names `withMiddleware()`

## v1.5.6

### Added
- `BootstrapRouteParser::getThrottleProtectedRouteFiles()` detects route files registered with any `throttle:*` middleware, in string or array form, on their group in `bootstrap/app.php`

### Fixed
- `login-throttling` no longer flags a route file whose group already carries throttle middleware in `bootstrap/app.php`, such as `Route::prefix('api/v1')->middleware(['api', 'throttle:api.rest'])->group(...)`
- `login-throttling` no longer flags a token management endpoint such as `GET /token/verify`, since the `token` and `oauth` keywords now trigger a check only on the credential-submitting methods `POST`, `any` and `match`

## v1.5.5

### Added
- `BootstrapRouteParser::getApiRegisteredRouteFiles()` detects route files registered under the `api` middleware group, reading both `require` statements in `routes/api.php` and `Route::middleware('api')->group(base_path(...))` chains in `bootstrap/app.php`

### Fixed
- `csrf-protection` no longer flags an API route file such as `routes/api-v1.php` registered under the `api` group through `withRouting(then: ...)`, which authenticates by Sanctum token and must not carry `web` middleware
- `BootstrapRouteParser::chainContainsMiddleware()` recognises the array form `->middleware(['api', 'throttle:api.rest'])`, not only the string form

## v1.5.4

### Fixed
- `fillable-foreign-key` reports each issue at the offending `$fillable` entry rather than the `protected $fillable = [` line, so an `@shieldci-ignore` comment placed on that entry is no longer ignored
- `naming-convention` reports a property or constant violation at its own line rather than the parent statement, so inline suppression works there too
- `password-security` reports a weak `password_hash()` option at the offending array entry rather than the call line

## v1.5.3

### Added
- `BootstrapRouteParser` (`ShieldCI\Support`) detects route files covered by the `web` middleware group through external registration, reading both `require` statements in `routes/web.php` and `Route::middleware('web')->group(base_path(...))` chains in `bootstrap/app.php`

### Fixed
- `csrf-protection` no longer flags a route file given `web` middleware externally through `withRouting(then: ...)`, such as `Route::middleware('web')->group(base_path('routes/auth.php'))`, since the file inherits CSRF protection from the group
- `login-throttling` no longer flags a login route in one of those externally registered files, since throttling applied to the whole `web` group covers it

## v1.5.2

### Changed
- `authentication-authorization` parses route files through a `RouteAuthVisitor` AST pass rather than 17 regular expressions, so multi-line chains and unusual indentation are read correctly

### Fixed
- `authentication-authorization` recognises a custom auth middleware class applied to a group as `Route::middleware(ClassName::class)->group()`, which a name-resolution ordering problem previously left unresolved
- `authentication-authorization` inherits middleware through a multi-segment chain such as `Route::prefix('api')->middleware('auth')->group()`
- `authentication-authorization` maps a legacy string route handler, `'Controller@method'` or `'Controller'`, to its controller method for auth statistics

## v1.5.1

### Fixed
- `authentication-authorization` no longer flags an invokable controller on a plain `Route::get()` route, since an unauthenticated GET marks the method intentionally public in the same way as `index` and `show`
- `authentication-authorization` no longer flags `FormRequest::authorize()` returning true when the request is injected into an auth-gated controller action, and skips orphaned `FormRequest` classes
- `authentication-authorization` no longer flags `Auth::user()`, `auth()->user()` or `$request->user()` inside a controller method that route or controller middleware verifiably protects

## v1.5.0

### Added
- `--category` accepts comma-separated values, so `--category=security,performance` runs both in one pass
- `AnalyzerManager::getByCategories()` filters the registered analyzer pool to any number of categories at once
- `shield:analyze` warns when `--analyzer` and `--category` are passed together, making explicit that `--category` is ignored

### Changed
- `--category` help text documents the comma-separated form

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
