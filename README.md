# ShieldCI Laravel Package

[![Latest Version on Packagist](https://img.shields.io/packagist/v/shieldci/laravel.svg)](https://packagist.org/packages/shieldci/laravel)
[![PHP Version](https://img.shields.io/packagist/php-v/shieldci/laravel.svg)](https://packagist.org/packages/shieldci/laravel)
[![Laravel Version](https://img.shields.io/badge/laravel-9.x--13.x-red.svg)](https://packagist.org/packages/shieldci/laravel)
[![License](https://img.shields.io/packagist/l/shieldci/laravel.svg)](https://packagist.org/packages/shieldci/laravel)
[![Tests](https://github.com/ShieldCI/laravel/actions/workflows/tests.yml/badge.svg)](https://github.com/ShieldCI/laravel/actions/workflows/tests.yml)
[![codecov](https://codecov.io/gh/ShieldCI/laravel/branch/master/graph/badge.svg)](https://codecov.io/gh/ShieldCI/laravel)
[![Documentation](https://img.shields.io/badge/docs-docs.shieldci.com-blue.svg)](https://docs.shieldci.com)

![ShieldCI terminal demo](https://raw.githubusercontent.com/ShieldCI/laravel/master/.github/assets/analyzer-terminal.gif)

Automated code analysis for Laravel applications — 73 open-source analyzers covering security, performance, reliability, code quality, and best practices.

Built on top of [`shieldci/analyzers-core`](https://github.com/ShieldCI/analyzers-core) - a shared, framework-agnostic foundation for static analysis tools.

## Requirements

- PHP 8.1 or higher
- Laravel 9.x, 10.x, 11.x, 12.x, 13.x

## Architecture

This package uses `shieldci/analyzers-core` for its core analyzer functionality, providing:
- Type-safe enums (Status, Category, Severity)
- Immutable value objects (Location, Issue, AnalyzerMetadata)
- Abstract base classes (AbstractAnalyzer, AbstractFileAnalyzer)
- AST parsing with nikic/php-parser
- Result formatters (JSON, Console)
- Comprehensive utilities (CodeHelper, FileParser)

## Installation

```bash
composer require shieldci/laravel
```

## Configuration

Publish the configuration file:

```bash
php artisan vendor:publish --tag=shieldci-config
```

Add your ShieldCI credentials to `.env` (your API token is displayed when you create a project in the [ShieldCI dashboard](https://shieldci.com/dashboard)):

```env
SHIELDCI_TOKEN=your-api-token
SHIELDCI_PROJECT_ID=your-project-id
```

## Usage

Run the analysis:

```bash
php artisan shield:analyze
```

### Options

Run a specific analyzer:
```bash
php artisan shield:analyze --analyzer=sql-injection
```

Run analyzers by category:
```bash
php artisan shield:analyze --category=security
```

Output as JSON:
```bash
php artisan shield:analyze --format=json
```

Save report to file:
```bash
php artisan shield:analyze --output=report.json
```

Send results to ShieldCI platform:
```bash
php artisan shield:analyze --report
```

Schedule analysis with trigger tracking:
```php
// Laravel 11+ (routes/console.php)
Schedule::command('shield:analyze --triggered-by=scheduled --report')->daily();

// Laravel 11+ (bootstrap/app.php)
->withSchedule(function (Schedule $schedule) {
    $schedule->command('shield:analyze --triggered-by=scheduled --report')->daily();
})

// Laravel 9-10 (app/Console/Kernel.php)
$schedule->command('shield:analyze --triggered-by=scheduled --report')->daily();
```

### Advanced Features

#### Baseline Support (Gradual Adoption)
Generate a baseline to suppress existing issues and only catch new ones:
```bash
# Generate baseline from current state (all analyzers, respects config)
php artisan shield:baseline

# Generate baseline for CI mode (only CI-compatible analyzers)
php artisan shield:baseline --ci

# Merge with existing baseline
php artisan shield:baseline --merge

# Analyze against baseline (only NEW issues reported)
php artisan shield:analyze --baseline
```

#### CI Mode (Optimized for CI/CD)
Skip slow or network-dependent analyzers in CI/CD:

```bash
# Run in CI mode (only CI-compatible analyzers)
php artisan shield:analyze --ci
```

Whitelist/blacklist specific analyzers in `config/shieldci.php`:

```php
'ci_mode_analyzers' => ['sql-injection', 'xss-vulnerabilities', 'csrf-protection'],
'ci_mode_exclude_analyzers' => ['vulnerable-dependencies', 'frontend-vulnerable-dependencies'],
```

#### Don't Report (Exit Code Control)
Run informational analyzers without failing CI:
```php
// config/shieldci.php
'dont_report' => [
    'missing-docblock',    // Informational only
    'commented-code',      // Won't fail CI
],
```

#### Compact Output
Limit displayed issues per check:
```bash
# Show only 3 issues per check
SHIELDCI_MAX_ISSUES=3 php artisan shield:analyze
```

#### Environment-Aware Analyzers
Some analyzers are only relevant in specific environments. ShieldCI automatically handles multi-environment setups through environment mapping.

**Standard environments** (no configuration needed):
- `local` - Local development
- `development` - Development server
- `staging` - Staging/pre-production
- `production` - Production
- `testing` - Automated testing

**Custom environments** (configure mapping):
```php
// config/shieldci.php
'environment_mapping' => [
    'production-us' => 'production',
    'production-eu' => 'production',
    'staging-preview' => 'staging',
    'prod-1' => 'production',
],
```

How it works:
- Analyzers declare which environments they're relevant for (e.g., `['production', 'staging']`)
- Custom environment names are automatically mapped to standard types
- Analyzers run only in their relevant environments

Example: AutoloaderOptimizationAnalyzer only runs in production/staging environments.

## Available Analyzers

ShieldCI includes **73 comprehensive analyzers** across five categories:

| Category | Count | Coverage |
|---|---|---|
| Security | 22 | Complete OWASP Top 10 2021 |
| Performance | 18 | Optimize speed and efficiency |
| Reliability | 13 | Ensure stability and correctness |
| Code Quality | 5 | Improve maintainability |
| Best Practices | 15 | Laravel-specific patterns |

→ [Full Analyzer Reference](https://docs.shieldci.com/analyzers/) — all 73 analyzers with examples and fix guidance

### ShieldCI Pro

[ShieldCI Pro](https://shieldci.com) adds **82 advanced analyzers** on top of the free package:

| Category | Count | Coverage |
|---|---|---|
| Security | 45 | Enterprise-grade vulnerability detection |
| Performance | 15 | Advanced performance optimization |
| Reliability | 15 | Production-grade resilience checks |
| Best Practices | 4 | Laravel architecture and conventions |
| Code Quality | 3 | Test coverage and quality analysis |

Highlights:
- **Security** — command injection, SSRF, XXE, object injection, GDPR compliance, hard-coded credentials, cryptographic weaknesses; framework-specific checks for Sanctum, Horizon, Telescope, Nova, Livewire, Inertia, and FilamentPHP
- **Performance** — Redis rate limiting, CDN/HTTP2/compression header analysis, lazy collection opportunities, FilamentPHP table optimization
- **Reliability** — health check and alerting config, job queue config, Horizon status and provisioning, Redis eviction policy, Laravel Vapor config

→ [Upgrade to Pro](https://shieldci.com)

## Configuration Options

See `config/shieldci.php` for all available configuration options.

### Fail Conditions

Configure when the analysis should fail:

```php
'fail_on' => 'critical', // never, critical, high, medium, low
'fail_threshold' => 80,  // Minimum score to pass (0-100)
```

### Paths

Configure which paths to analyze:

```php
'paths' => [
    'analyze' => ['app', 'config', 'database', 'routes'],
],

'excluded_paths' => [
    'vendor/*',
    'node_modules/*',
    'storage/*',
],
```

## Creating Custom Analyzers

Quick example:

```php
<?php

namespace ShieldCI\Analyzers\Security;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\ValueObjects\{AnalyzerMetadata, Location};
use ShieldCI\AnalyzersCore\Enums\{Category, Severity};

class MyAnalyzer extends AbstractFileAnalyzer
{
    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'my-analyzer',
            name: 'My Custom Analyzer',
            description: 'Checks for custom security issues',
            category: Category::Security,
            severity: Severity::High,
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        // Your analysis logic
        $issues = [];

        foreach ($this->getPhpFiles() as $file) {
            // Analyze files
        }

        return empty($issues)
            ? $this->passed('No issues found')
            : $this->failed('Issues detected', $issues);
    }
}
```

## Testing

```bash
composer test           # 4,000+ tests
composer test-coverage  # 98%+ code coverage
composer analyse        # PHPStan Level 9
```

## Documentation

- [Full Documentation](https://docs.shieldci.com) - Installation, configuration, and analyzer guides
- [Getting Started](https://docs.shieldci.com/getting-started/installation) - Quick start guide
- [Analyzer Reference](https://docs.shieldci.com/analyzers/) - All 73 analyzers with examples and fix guidance
- [Analyzers Core](https://github.com/ShieldCI/analyzers-core/blob/master/README.md) - Core package documentation

## License

MIT License. See LICENSE file for details.
