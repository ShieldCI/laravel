# ShieldCI Laravel Package

Modern security and code quality analysis for Laravel applications.

Built on top of [`shieldci/analyzers-core`](https://github.com/shieldci/analyzers-core) - a shared, framework-agnostic foundation for static analysis tools.

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

Add your ShieldCI credentials to `.env`:

```env
SHIELDCI_ENABLED=true
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
php artisan shield:analyze --analyzer=sql-injection-detector
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

Don't send results to ShieldCI API:
```bash
php artisan shield:analyze --no-send
```

## Available Analyzers

ShieldCI includes 21 comprehensive security analyzers providing complete OWASP Top 10 2021 coverage:

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
