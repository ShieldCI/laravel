# ShieldCI Laravel Package

> **⚠️ Initial Development Release (v0.1.x)** - This package is under active development. APIs may change between minor versions until v1.0.0 is released.

Modern security and code quality analysis for Laravel applications with 73 comprehensive analyzers covering security, performance, reliability, and code quality.

Built on top of [`shieldci/analyzers-core`](https://github.com/shieldci/analyzers-core) (v0.1.x) - a shared, framework-agnostic foundation for static analysis tools.

## Requirements

- PHP 8.1 or higher
- Laravel 9.0 or higher

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

Enable ShieldCI in your `.env`:

```env
SHIELDCI_ENABLED=true
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
# Configure in config/shieldci.php
'ci_mode' => env('SHIELDCI_CI_MODE', false),
'ci_mode_analyzers' => ['sql-injection', 'xss-detection', 'csrf-analyzer'],
'ci_mode_exclude_analyzers' => ['vulnerable-dependency', 'unused-view'],

# Run in CI
SHIELDCI_CI_MODE=true php artisan shield:analyze
```

#### Don't Report (Exit Code Control)
Run informational analyzers without failing CI:
```php
// config/shieldci.php
'dont_report' => [
    'missing-docblock',    // Informational only
    'select-asterisk',     // Won't fail CI
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
- **22 Security Analyzers** - Complete OWASP Top 10 2021 coverage
- **18 Performance Analyzers** - Optimize application speed and efficiency
- **13 Reliability Analyzers** - Ensure application stability and correctness
- **5 Code Quality Analyzers** - Improve maintainability and code standards
- **15 Best Practices Analyzers** - Enforce Laravel-specific best practices

### Security Analyzers (22)

Providing complete OWASP Top 10 2021 coverage:

### Injection Vulnerabilities (A03:2021)
- **SQL Injection Analyzer** - Detects unsafe database queries with string concatenation or user input
- **XSS Analyzer (Dual Protection)** ⭐ **ENHANCED**
  - **Static Code Analysis** (always runs in CI/Production):
    - Detects unescaped Blade output `{!! $var !!}`
    - Identifies unsafe JavaScript embedding
    - Finds Response::make() issues
    - Checks for superglobal echoing
  - **HTTP Header Verification** (production only):
    - Validates Content-Security-Policy (CSP) headers
    - Ensures script-src/default-src directives present
    - Blocks unsafe-inline and unsafe-eval directives

### Broken Access Control (A01:2021)
- **Authentication Analyzer** - Validates route authentication and authorization
- **Fillable Foreign Key Analyzer** - Detects foreign key fields in mass assignment fillable arrays
- **CSRF Analyzer** - Ensures CSRF protection on forms and AJAX requests

### Cryptographic Failures (A02:2021)
- **App Key Analyzer** - Validates APP_KEY configuration and cipher settings
- **Hashing Strength Analyzer** - Checks password hashing algorithms (bcrypt rounds, Argon2 settings)
- **Cookie Security Analyzer** - Validates HttpOnly, Secure, and SameSite cookie flags
- **HSTS Header Analyzer** - Ensures Strict-Transport-Security header for HTTPS applications

### Insecure Design (A04:2021)
- **Mass Assignment Analyzer** - Detects models without fillable/guarded and unsafe create()/update() calls
- **Unguarded Models Analyzer** - Identifies Model::unguard() usage that disables protection
- **Login Throttling Analyzer** - Validates rate limiting on authentication endpoints

### Security Misconfiguration (A05:2021)
- **Debug Mode Analyzer** - Detects debug mode enabled in production and exposed debug data
- **PHP Ini Analyzer** - Validates PHP configuration security settings
- **File Permissions Analyzer** - Checks directory and file permissions for security issues
- **Environment File Security Analyzer** - Validates .env location, permissions, git exclusion, and secrets
- **Environment File HTTP Accessibility Analyzer** - Verifies .env is not accessible via web server (runtime check)

### Vulnerable and Outdated Components (A06:2021)
- **Vulnerable Dependency Analyzer** - Scans Composer dependencies for known CVEs using `composer audit`
- **Frontend Vulnerable Dependency Analyzer** - Scans npm/yarn packages for security vulnerabilities
- **Up-to-Date Dependency Analyzer** - Checks for outdated packages with available security patches
- **Stable Dependency Analyzer** - Validates stable version usage (no dev/alpha/beta)
- **License Analyzer** - Ensures dependencies use legally acceptable licenses (detects GPL/AGPL issues)

### Performance Analyzers (18)

Optimize your Laravel application for production:

- **Autoloader Optimization Analyzer** - Ensures optimized Composer autoloader in production
- **Cache Driver Analyzer** - Validates production-ready cache drivers (Redis, Memcached)
- **Cache Header Analyzer** - Checks HTTP cache headers for static assets
- **Collection Call Analyzer** - Detects inefficient collection usage patterns (PHPStan/Larastan-powered)
- **Config Caching Analyzer** - Validates configuration caching in production
- **Debug Log Analyzer** - Detects debug-level logging in production environments
- **Dev Dependency Analyzer** - Ensures dev dependencies aren't in production
- **Env Call Analyzer** - Detects env() calls outside configuration files
- **Horizon Suggestion Analyzer** - Recommends Laravel Horizon for Redis queue management
- **Minification Analyzer** - Checks asset minification for production
- **Mysql Single Server Analyzer** - Validates database configuration
- **Opcache Analyzer** - Ensures OPcache is enabled in production
- **Queue Driver Analyzer** - Validates production queue configuration
- **Route Caching Analyzer** - Ensures route caching in production
- **Session Driver Analyzer** - Validates production session storage
- **Shared Cache Lock Analyzer** - Checks cache lock configuration
- **Unused Global Middleware Analyzer** - Detects unnecessary global middleware
- **View Caching Analyzer** - Validates Blade view compilation caching

### Reliability Analyzers (13)

Ensure application stability and correctness:

**Configuration & Infrastructure (8):**
- **Cache Prefix Analyzer** - Prevents cache collisions in shared environments
- **Cache Status Analyzer** - Validates cache connectivity
- **Composer Validation Analyzer** - Ensures composer.json integrity
- **Database Status Analyzer** - Monitors database connections
- **Directory Write Permissions Analyzer** - Checks critical directory permissions
- **Env File Analyzer** - Validates .env file existence, readability, and checks for broken symlinks
- **Env Variable Analyzer** - Ensures all required variables from .env.example are defined in .env
- **Env Example Analyzer** - Ensures all variables from .env are documented in .env.example

**PHPStan Static Analysis (1 consolidated analyzer, 13 categories):**
- **PHPStan Analyzer** - Comprehensive static analysis detecting 13 categories:
  - Dead Code - Unreachable statements, unused variables
  - Deprecated Code - Usage of deprecated methods/classes
  - Foreach Iterable - Invalid foreach with non-iterable values
  - Invalid Function Calls - Undefined or incorrectly parameterized functions
  - Invalid Imports - Invalid use statements for non-existent classes
  - Invalid Method Calls - Undefined or incorrectly parameterized methods
  - Invalid Method Overrides - Incompatible method signature overrides
  - Invalid Offset Access - Invalid array offset access and type mismatches
  - Invalid Property Access - Access to undefined or inaccessible properties
  - Missing Model Relations - References to non-existent Eloquent relations
  - Missing Return Statements - Methods with missing return statements
  - Undefined Constants - References to undefined constants
  - Undefined Variables - References to undefined variables

**Application State (4):**
- **Custom Error Page Analyzer** - Validates error page customization
- **Maintenance Mode Analyzer** - Checks maintenance status
- **Queue Timeout Analyzer** - Prevents job duplication with proper timeouts
- **Up-to-Date Migrations Analyzer** - Detects pending migrations

### Code Quality Analyzers (5)

Improve code maintainability and enforce best practices:

- **Commented Code Analyzer** - Detects commented-out code that should be removed
- **Method Length Analyzer** - Flags overly long methods that should be refactored
- **Missing DocBlock Analyzer** - Checks for missing PHPDoc blocks on classes and methods
- **Naming Convention Analyzer** - Enforces PSR naming conventions (classes, methods, properties)
- **Nesting Depth Analyzer** - Detects excessive nesting levels that reduce readability

### Best Practices Analyzers (15)

Enforce Laravel-specific best practices and architectural patterns:

**Query & Database Best Practices (5):**
- **Eloquent N+1 Query Analyzer** - Identifies missing eager loading causing N+1 queries
- **Mixed Query Builder Eloquent Analyzer** - Detects inconsistent mixing of Query Builder and Eloquent ORM
- **Chunk Missing Analyzer** - Identifies large dataset queries missing chunk() for memory efficiency
- **Missing Database Transactions Analyzer** - Detects operations that should be wrapped in transactions
- **PHP Side Filtering Analyzer** - Finds filtering done in PHP that should be in SQL queries

**Architecture & Structure (3):**
- **Logic in Routes Analyzer** - Identifies business logic in route files
- **Logic in Blade Analyzer** - Detects complex logic in Blade templates
- **Fat Model Analyzer** - Identifies models with too many responsibilities

**Dependency Injection & Service Container (2):**
- **Helper Function Abuse Analyzer** - Flags overuse of Laravel helper functions
- **Service Container Resolution Analyzer** - Flags manual service resolution (app(), resolve())

**Configuration & Error Handling (3):**
- **Config Outside Config Analyzer** - Detects configuration values not in config files
- **Missing Error Tracking Analyzer** - Identifies missing error tracking integration
- **Silent Failure Analyzer** - Detects suppressed exceptions and errors

**Infrastructure (2):**
- **Hardcoded Storage Paths Analyzer** - Detects hardcoded paths instead of Laravel helpers
- **Framework Override Analyzer** - Identifies dangerous framework core overrides

All analyzers are automatically discovered and registered by the service provider.

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
composer test
```

## Documentation

- [Analyzers Core](https://github.com/ShieldCI/analyzers-core/blob/master/README.md) - Core package documentation

## License

MIT License. See LICENSE file for details.
