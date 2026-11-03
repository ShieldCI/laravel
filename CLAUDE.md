# ShieldCI Laravel Package (Free)

## Purpose
Free Laravel package with 73 analyzers for security, performance, reliability, code quality, and best practices.

## Stack
- PHP 8.1+
- Laravel 9 to 13 (`illuminate/*` constraints in `composer.json`)
- Depends on: `shieldci/analyzers-core` (framework-agnostic foundation, including AST parsing via `nikic/php-parser`)
- `larastan/larastan` and `phpstan/phpstan` are production dependencies: analyzers run PHPStan
- PHPStan Level 9, pinned in `phpstan.neon`

## Dependencies

### analyzers-core (Foundation)
**Path**: `vendor/shieldci/analyzers-core/` (resolved from Packagist; don't edit it in `vendor/`)
**Why**: All Laravel analyzers extend base classes from core. Core provides the framework-agnostic foundation.

**Key files to reference** (under `vendor/shieldci/analyzers-core/src/`):
- `Abstracts/AbstractFileAnalyzer.php` - Base class for file-based analyzers
- `Abstracts/AbstractAnalyzer.php` - Core analyzer logic (timing, error handling, `createIssue()`, `createIssueWithSnippet()`, `$runInCI`)
- `Contracts/` - Interfaces (AnalyzerInterface, ResultInterface, ParserInterface)
- `Enums/` - Type-safe enums (Status, Category, Severity)
- `ValueObjects/` - Immutable objects (Issue, Location, AnalyzerMetadata, CodeSnippet)
- `Support/AstParser.php` - PHP AST parsing
- `Support/FileParser.php` - File reading, line extraction, `stripAllComments()`
- `Support/ConfigFileHelper.php` - Config file analysis
- `Support/CodeHelper.php` - Code analysis utilities

**Important**: Never duplicate code from analyzers-core. Always import and extend. Keep Laravel-specific logic in this package, framework-agnostic utilities in core.

## Architecture

### Package Structure
```
laravel/
├── config/
│   └── shieldci.php          # Published config (every key is documented inline)
├── src/
│   ├── Analyzers/
│   │   ├── Security/         # 22 analyzers
│   │   ├── Performance/      # 18 analyzers
│   │   ├── Reliability/      # 13 analyzers
│   │   ├── CodeQuality/      # 5 analyzers
│   │   └── BestPractices/    # 15 analyzers
│   ├── Commands/             # AnalyzeCommand (shield:analyze), BaselineCommand (shield:baseline)
│   ├── Concerns/             # Shared analyzer traits
│   ├── Http/Client/          # ShieldCIClient (report upload)
│   ├── Support/              # Shared Laravel-aware helpers (EloquentModelDetector, BootstrapRouteParser, MiddlewareThrottleDetector, ...)
│   ├── AnalyzerManager.php
│   └── ShieldCIServiceProvider.php
├── tests/
│   ├── AnalyzerTestCase.php  # Base class and helpers for analyzer tests
│   ├── Fixtures/
│   └── Unit/                 # Mirrors src/
└── composer.json
```

**Why this structure**: Extends `analyzers-core` abstracts and adds Laravel-specific analyzers. Helpers that need Laravel live in `src/Support/`, never in core.

### Analyzer Pattern
Excerpt from `src/Analyzers/Security/XssAnalyzer.php`:

```php
namespace ShieldCI\Analyzers\Security;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;

class XssAnalyzer extends AbstractFileAnalyzer
{
    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'xss-vulnerabilities',
            name: 'XSS Vulnerabilities Analyzer',
            description: 'Detects XSS vulnerabilities via code analysis and HTTP header verification (dual protection)',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['xss', 'cross-site-scripting', 'security', 'blade', 'csp', 'headers'],
            timeToFix: 30
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        // Analysis logic...
    }
}
```

**CI gating**: an analyzer that must not run in CI declares `public static bool $runInCI = false;`
(the core default is `true`), as `DebugLogAnalyzer` does. Never read `shieldci.ci_mode` inside
an analyzer to gate itself; `AnalyzerManager` applies the flag and the `ci_mode_analyzers` /
`ci_mode_exclude_analyzers` config.

### Artisan Commands

```bash
php artisan shield:analyze                                      # Run all analyzers
php artisan shield:analyze --analyzer=sql-injection,xss-vulnerabilities
php artisan shield:analyze --category=security,performance
php artisan shield:analyze --format=json --output=report.json   # console|json
php artisan shield:analyze --baseline                           # Only issues not in the baseline
php artisan shield:analyze --ci                                 # Only CI-compatible analyzers
php artisan shield:analyze --report                             # Upload the report (needs token and project_id)
php artisan shield:baseline [--merge] [--ci]                    # Write the baseline file
```

`--report` (or `report.send_to_api`) uploads `AnalysisReport::toArray()` through
`ShieldCIClient`. The payload carries each issue's file, line, message and recommendation,
and its code snippet, so it includes source fragments.

## Testing Strategy

### Analyzer Tests
Excerpt from `tests/Unit/Analyzers/Security/XssAnalyzerTest.php`:

```php
namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\XssAnalyzer;
use ShieldCI\Support\OriginReachability\OriginReachabilityChecker;
use ShieldCI\Tests\AnalyzerTestCase;

class XssAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): XssAnalyzer
    {
        // Resolves the router and kernel from $this->app; see the file.
        return new XssAnalyzer($router, $kernel, $this->parser, new OriginReachabilityChecker);
    }

    public function test_detects_unescaped_blade_output_with_user_input(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    <h1>{!! $title !!}</h1>
    <div>{!! request('content') !!}</div>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['page.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Unescaped blade output', $result);
    }
}
```

**Key test helpers** (from `AnalyzerTestCase`):
- `createTempDirectory(array $files)` - Fixture directory from a path => contents map, returns the path
- `createTempPhpFile(string $code)` - Single-file fixture
- `assertPassed` / `assertFailed` / `assertWarning` / `assertSkipped` / `assertError` - Status assertions
- `assertHasIssueContaining(string $text, $result)`, `assertIssueCount(int $expected, $result)`
- `$this->parser` - The shared `AstParser` to inject into analyzers that take one

**Argument order**: the needle comes FIRST - `assertHasIssueContaining('text', $result)`, not
`($result, 'text')`. The wrong order is a TypeError, so it reads as an errored test rather than
a failing one.

## Configuration File

`config/shieldci.php` is the source of truth; every key is documented inline. The main groups:
`enabled`, `timeout`, `memory_limit`; platform credentials (`token`, `project_id`, `api_url`);
analyzer selection (`analyzers`, `disabled_analyzers`, `ci_mode_analyzers`,
`ci_mode_exclude_analyzers`); scope (`paths`, `excluded_paths`); suppression (`dont_report`,
`baseline_file`, `ignore_errors`); output (`report`); and the build gate (`fail_on`, default
`high`, and `fail_threshold`).

## Distribution

Published to https://packagist.org/packages/shieldci/laravel. Installation:
`composer require shieldci/laravel`.

## Development Workflow

### After Every Change

```bash
composer check     # format-check + analyse + test: the CI gate
composer quality   # format + analyse + test-coverage: before opening a PR
```

Use the composer scripts, not raw `vendor/bin/*` calls; the level is pinned in `phpstan.neon`,
so no `--level` flag is needed. There is no `artisan` in this repo: `php artisan test` prints
`Could not open input file: artisan` and exits 0, so it reads as a pass that never ran. Don't
pipe `composer check` into `tail`; the pipe reports `tail`'s exit code.

### Available Scripts

```bash
composer test                 # Run all tests
composer test -- --filter=XssAnalyzerTest   # Run one test class
composer test-coverage        # HTML + text + clover coverage report
composer test-coverage-check  # Coverage run that fails on risky tests or warnings
composer analyse              # PHPStan Level 9 + Larastan
composer format               # Auto-fix with Pint
composer format-check         # Check style without fixing
composer check                # Verify everything (CI simulation)
composer quality              # Format + Analyse + Coverage
```

### Testing Philosophy

1. **Every analyzer** has tests with both a failing fixture and a passing one
2. **Edge cases** covered (empty files, syntax errors, unpublished config)
3. **CI compatibility** tested (`$runInCI`)
4. **Data providers** carry both the `@dataProvider` annotation and the `#[DataProvider]`
   attribute: PHPUnit 9 (the Laravel 9 CI leg) reads only the annotation, PHPUnit 10+ only the
   attribute

### Changelog Style

`CHANGELOG.md` and each GitHub release body must hold **identical text**. There is no
automation between them, so after tagging, copy the section into the release verbatim.

Write every entry this way:

1. **Name the public handle, not the class.** An analyzer is `` `logic-in-blade` ``, never
   `LogicInBladeAnalyzer`. The id from `metadata()` is what users see in output, config
   and `--analyzer=`. A command (`` `shield:analyze` ``), a config key
   (`` `shieldci.report.format` ``) or an issue code (`` `blade-inline-php` ``) is equally
   valid as the subject. Exception: name the class when it has no analyzer id, which covers
   support classes (`BootstrapRouteParser`, `EloquentModelDetector`, `SeededTableScanner`),
   or when the entry *introduces that class* under `### Added`.
2. **No `Class:` colon form.** `` `logic-in-blade` skips any path containing `/vendor/` ``
   reads as a sentence; `` `LogicInBladeAnalyzer`: the structural pass now ... `` does not.
3. **One sentence**: the behaviour change, then the concrete trigger or consequence after a
   comma: `so ...`, `instead of ...`, `rather than ...`, `such as ...`. Keep it under ~325
   characters; split into separate bullets rather than chaining claims.
4. **Plain keyboard punctuation.** No em dashes, en dashes or curly quotes. One semicolon
   joining two related clauses is fine; three are a sign the bullet should be several.
5. **No trailing period.**
6. **Issue reference last**: `(#341)`, or `(#407, #409, #413)` when several PRs made one
   user-visible change. Repeat the reference on each bullet when one change spans several.
7. **Sections `### Added`, `### Changed`, `### Fixed`**, in that order.
8. **Dependency bumps** go under `### Changed`: ``Requires `pkg ^X` (was `^Y`), <why> (#N)``.
9. **Only user-observable changes.** An internal refactor, a test-suite fix or a PHPStan
   cleanup does not get a line, however large the diff.
10. **No nested bullets.** A change spanning several analyzers becomes one flat bullet per
    distinct behaviour, each carrying the issue reference.

Reference entry:

```
- `cache-driver` assesses the driver when `config/cache.php` has not been published, instead of erroring out on a stock Laravel 11+ skeleton (#356)
```

### Versioning

Grade a release by what a user sees on upgrading **without touching their code**. The
findings are the API: `^1.x` pulls any minor or patch into their CI unasked. Adapted from
ESLint's policy, with new detections kept out of major as a security scanner's are.

| Bump | Qualifies |
|------|-----------|
| **Patch** | Fixes that only *remove* findings (false positives), crashes or `Status::Error`; wording that leaves fingerprints unchanged; docs. `composer.json` `require` unchanged |
| **Minor** | A new analyzer; a fix that *adds* findings (false negatives); any rehashed fingerprint, since `dont_report` entries stop matching; a severity change; a new config key; a raised minimum on any `require` entry |
| **Major** | Removing or renaming an analyzer id or config key; dropping a PHP or Laravel version; changing exit-code semantics, output format or what `fail_on` means |

Shortcut: **any bullet under `### Changed`, or any `### Fixed` bullet that adds findings,
makes the release at least a minor.** A change that starts failing a default `fail_on: high`
build stays a minor, but its `### Changed` bullet must say so.

Pre-policy releases graded some rehashes and dependency bumps as patches; do not cite them
as precedent.

### Updating CLAUDE.md

**When to update**:
- New analyzer patterns emerge
- Testing approach changes
- New dependencies added
- Common issues discovered

**What NOT to add**:
- A list of every analyzer (`src/Analyzers/` is the list)
- Implementation details of each analyzer
- Temporary workarounds
- Counts that change with every PR (tests, assertions, coverage)
- Anything that only resolves in a local workspace: sibling-repo paths, internal docs or
  other projects. This repository is public; that belongs in the gitignored `CLAUDE.local.md`

## When Building Here

1. **Check core first** - Framework-agnostic features belong in analyzers-core instead
2. **Check existing analyzers in the same category** - Follow established patterns
3. **Test immediately** - Every analyzer needs a failing and a passing fixture
4. **Shared helpers report, not grade** - A `src/Support/` helper describes the defect; the
   consuming analyzer assigns the severity

## What NOT to Do

❌ Don't break backward compatibility (analyzer ids and config keys are public API)
❌ Don't add Laravel-specific code to analyzers-core (keep core framework-agnostic)
❌ Don't skip tests (every analyzer needs fixture-based tests)
❌ Don't commit with PHPStan errors (Level 9 required)
❌ Don't modify core interfaces (would break analyzers-core compatibility)
❌ Don't add "Co-Authored-By: Claude Code" or "Generated with Claude Code" attribution when committing code
❌ Don't add a "Test plan" section to pull request bodies
