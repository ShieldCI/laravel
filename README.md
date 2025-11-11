# ShieldCI Laravel Package

> **⚠️ Initial Development Release (v0.1.x)** - This package is under active development. APIs may change between minor versions until v1.0.0 is released.

Modern security and code quality analysis for Laravel applications with 81 comprehensive analyzers covering security, performance, reliability, and code quality.

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

## Available Analyzers

ShieldCI includes **99 comprehensive analyzers** across five categories:
- **21 Security Analyzers** - Complete OWASP Top 10 2021 coverage
- **16 Performance Analyzers** - Optimize application speed and efficiency
- **24 Reliability Analyzers** - Ensure application stability and correctness
- **15 Code Quality Analyzers** - Improve maintainability and code standards
- **23 Best Practices Analyzers** - Enforce Laravel-specific best practices

### Security Analyzers (21)

Providing complete OWASP Top 10 2021 coverage:

### Injection Vulnerabilities (A03:2021)
- **SQL Injection Analyzer** - Detects unsafe database queries with string concatenation or user input
- **XSS Analyzer** - Identifies unescaped output, unsafe JavaScript embedding, and Response::make() issues

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

### Vulnerable and Outdated Components (A06:2021)
- **Vulnerable Dependency Analyzer** - Scans Composer dependencies for known CVEs using `composer audit`
- **Frontend Vulnerable Dependency Analyzer** - Scans npm/yarn packages for security vulnerabilities
- **Up-to-Date Dependency Analyzer** - Checks for outdated packages with available security patches
- **Stable Dependency Analyzer** - Validates stable version usage (no dev/alpha/beta)
- **License Analyzer** - Ensures dependencies use legally acceptable licenses (detects GPL/AGPL issues)

### Performance Analyzers (16)

Optimize your Laravel application for production:

- **Autoloader Optimization Analyzer** - Ensures optimized Composer autoloader in production
- **Cache Driver Analyzer** - Validates production-ready cache drivers (Redis, Memcached)
- **Cache Header Analyzer** - Checks HTTP cache headers for static assets
- **Collection Call Analyzer** - Detects inefficient collection usage patterns
- **Config Caching Analyzer** - Validates configuration caching in production
- **Dev Dependency Analyzer** - Ensures dev dependencies aren't in production
- **Env Call Analyzer** - Detects env() calls outside configuration files
- **Minification Analyzer** - Checks asset minification for production
- **Mysql Single Server Analyzer** - Validates database configuration
- **Opcache Analyzer** - Ensures OPcache is enabled in production
- **Queue Driver Analyzer** - Validates production queue configuration
- **Route Caching Analyzer** - Ensures route caching in production
- **Session Driver Analyzer** - Validates production session storage
- **Shared Cache Lock Analyzer** - Checks cache lock configuration
- **Unused Global Middleware Analyzer** - Detects unnecessary global middleware
- **View Caching Analyzer** - Validates Blade view compilation caching

### Reliability Analyzers (24)

Ensure application stability and correctness:

**Configuration & Infrastructure (8):**
- **Cache Prefix Analyzer** - Prevents cache collisions in shared environments
- **Cache Status Analyzer** - Validates cache connectivity
- **Composer Validation Analyzer** - Ensures composer.json integrity
- **Database Status Analyzer** - Monitors database connections
- **Directory Write Permissions Analyzer** - Checks critical directory permissions
- **Env File Analyzer** - Validates .env file existence
- **Env Variable Analyzer** - Ensures all required variables are defined
- **Queue Timeout Analyzer** - Prevents job duplication with proper timeouts

**PHPStan-Powered Static Analysis (13):**
- **Dead Code Analyzer** - Detects unreachable code
- **Deprecated Code Analyzer** - Identifies deprecated features
- **Foreach Iterable Analyzer** - Validates iterable types
- **Invalid Function Call Analyzer** - Catches undefined functions
- **Invalid Import Analyzer** - Detects invalid use statements
- **Invalid Method Call Analyzer** - Finds non-existent methods
- **Invalid Method Override Analyzer** - Validates signatures
- **Invalid Offset Analyzer** - Checks array access
- **Invalid Property Access Analyzer** - Detects undefined properties
- **Missing Model Relation Analyzer** - Finds missing Eloquent relations
- **Missing Return Statement Analyzer** - Ensures proper returns
- **Undefined Constant Analyzer** - Catches undefined constants
- **Undefined Variable Analyzer** - Detects undefined variables

**Application State (3):**
- **Custom Error Page Analyzer** - Validates error page customization
- **Maintenance Mode Analyzer** - Checks maintenance status
- **Up-to-Date Migrations Analyzer** - Detects pending migrations

### Code Quality Analyzers (15)

Improve code maintainability and enforce best practices:

**Complexity & Size (7):**
- **Class Length Analyzer** - Detects classes exceeding size limits (default: 500 lines)
- **Cognitive Complexity Analyzer** - Measures cognitive load of methods
- **Cyclomatic Complexity Analyzer** - Detects complex methods (default threshold: 10)
- **Method Length Analyzer** - Flags overly long methods
- **Nesting Depth Analyzer** - Detects excessive nesting levels
- **Parameter Count Analyzer** - Identifies methods with too many parameters
- **Long Parameter List Analyzer** - Validates parameter list lengths

**Code Duplication & Naming (3):**
- **Duplicate Code Analyzer** - Detects similar code blocks (6+ lines, 85%+ similarity)
- **Inconsistent Naming Analyzer** - Finds mixed naming styles (snake_case vs camelCase)
- **Naming Convention Analyzer** - Enforces PSR naming conventions

**Maintainability (5):**
- **Complex Conditional Analyzer** - Detects complex conditional expressions
- **Magic Number Analyzer** - Finds hard-coded numbers that should be constants
- **Missing DocBlock Analyzer** - Checks for missing PHPDoc blocks
- **Commented Code Analyzer** - Detects commented-out code
- **Todo Comment Analyzer** - Finds TODO/FIXME comments in codebase

### Best Practices Analyzers (23)

Enforce Laravel-specific best practices and architectural patterns:

**Query & Database Best Practices (8):**
- **Eloquent N+1 Query Analyzer** - Identifies missing eager loading causing N+1 queries
- **Missing Model Scope Analyzer** - Detects repeated query patterns that should be extracted to model scopes
- **Mixed Query Builder Eloquent Analyzer** - Detects inconsistent mixing of Query Builder and Eloquent ORM
- **Raw Eloquent Avoidance Analyzer** - Identifies overuse of raw SQL queries instead of Eloquent
- **Select Asterisk Analyzer** - Detects SELECT * queries that should specify columns
- **Chunk Missing Analyzer** - Identifies large dataset queries missing chunk() for memory efficiency
- **Missing Database Transactions Analyzer** - Detects operations that should be wrapped in transactions
- **PHP Side Filtering Analyzer** - Finds filtering done in PHP that should be in SQL queries

**Architecture & Structure (5):**
- **MVC Structure Violation Analyzer** - Detects violations of MVC pattern separation
- **Logic in Routes Analyzer** - Identifies business logic in route files
- **Logic in Blade Analyzer** - Detects complex logic in Blade templates
- **Query Builder in Controller Analyzer** - Detects DB queries in controllers (recommends repository pattern)
- **Fat Model Analyzer** - Identifies models with too many responsibilities

**Dependency Injection & Service Container (3):**
- **Facade Usage Analyzer** - Detects facade usage (recommends dependency injection)
- **Helper Function Abuse Analyzer** - Flags overuse of Laravel helper functions
- **Service Container Resolution Analyzer** - Flags manual service resolution (app(), resolve())

**Configuration & Error Handling (5):**
- **Config Outside Config Analyzer** - Detects configuration values not in config files
- **Environment Check Smell Analyzer** - Detects environment checks that should use configuration
- **Missing Error Tracking Analyzer** - Identifies missing error tracking integration
- **Silent Failure Analyzer** - Detects suppressed exceptions and errors
- **Generic Exception Catch Analyzer** - Finds overly broad exception handling

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
