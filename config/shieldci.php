<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Analysis Configuration
    |--------------------------------------------------------------------------
    |
    | Control the overall behavior of ShieldCI analysis.
    |
    */

    'enabled' => env('SHIELDCI_ENABLED', true),

    'timeout' => env('SHIELDCI_TIMEOUT', 300), // seconds

    'memory_limit' => env('SHIELDCI_MEMORY_LIMIT', '512M'),

    /*
    |--------------------------------------------------------------------------
    | CI Mode Configuration
    |--------------------------------------------------------------------------
    |
    | Configure ShieldCI behavior in CI/CD environments.
    |
    */

    'ci_mode' => env('SHIELDCI_CI_MODE', false),

    'ci_mode_analyzers' => [
        // Whitelist: If specified, ONLY these analyzers run in CI mode
        // Leave empty to use the default $runInCI property from each analyzer
        // Example: 'sql-injection', 'xss-detection', 'csrf-analyzer'
    ],

    'ci_mode_exclude_analyzers' => [
        // Blacklist: Additionally exclude these analyzers in CI mode
        // These override the analyzer's $runInCI property
        // Example: 'collection-call-analyzer', 'code-smell-detector'
    ],

    /*
    |--------------------------------------------------------------------------
    | Environment-Specific Analyzers
    |--------------------------------------------------------------------------
    |
    | Skip environment-specific analyzers when set to true.
    | Useful for excluding checks specific to non-local environments when running in local.
    |
    */

    'skip_env_specific' => env('SHIELDCI_SKIP_ENV_SPECIFIC', false),

    /*
    |--------------------------------------------------------------------------
    | Analyzer Categories
    |--------------------------------------------------------------------------
    |
    | Enable or disable entire categories of analyzers.
    | Available: security, performance, reliability, code_quality, best_practices
    |
    */

    'analyzers' => [
        'security' => true,
        'performance' => true,
        'reliability' => true,
        'code_quality' => true,
        'best_practices' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Disabled Analyzers
    |--------------------------------------------------------------------------
    |
    | Disable specific analyzers by their ID.
    |
    */

    'disabled_analyzers' => [
        // 'sql-injection',
    ],

    /*
    |--------------------------------------------------------------------------
    | Don't Report Analyzers
    |--------------------------------------------------------------------------
    |
    | Analyzers listed here will run but won't affect the exit code.
    | Useful for informational checks that shouldn't fail CI/CD.
    |
    */

    'dont_report' => [
        // 'missing-error-tracking',
        // 'select-asterisk',
        // 'missing-docblock',
    ],

    /*
    |--------------------------------------------------------------------------
    | Paths Configuration
    |--------------------------------------------------------------------------
    |
    | Define which paths to analyze and which to exclude.
    |
    */

    'paths' => [
        'analyze' => [
            'app',
            'config',
            'database',
            'routes',
            'resources/views',
        ],
    ],

    'excluded_paths' => [
        'vendor/*',
        'node_modules/*',
        'storage/*',
        'bootstrap/cache/*',
        'tests/*',
    ],

    /*
    |--------------------------------------------------------------------------
    | Reporting Configuration
    |--------------------------------------------------------------------------
    |
    | Configure how analysis results are reported.
    |
    */

    'report' => [
        'format' => env('SHIELDCI_REPORT_FORMAT', 'console'), // console, json

        'output_file' => null,

        'show_recommendations' => true,

        'show_code_snippets' => true,

        'max_issues_per_check' => env('SHIELDCI_MAX_ISSUES', 5), // Limit displayed issues per check
    ],

    /*
    |--------------------------------------------------------------------------
    | Baseline Configuration
    |--------------------------------------------------------------------------
    |
    | Baseline support allows you to suppress existing issues and only
    | report new ones. Use 'php artisan shield:baseline' to generate.
    |
    */

    'baseline_file' => base_path('.shieldci-baseline.json'),

    /*
    |--------------------------------------------------------------------------
    | Ignoring Errors
    |--------------------------------------------------------------------------
    |
    | Use this config option to ignore specific errors.
    | Run php artisan shield:baseline to auto-generate this.
    |
    */

    'ignore_errors' => [],

    /*
    |--------------------------------------------------------------------------
    | Guest URL Path
    |--------------------------------------------------------------------------
    |
    | Specify a guest url or path (preferably your app's login url) here.
    | This is used by HTTP-based analyzers to inspect your application.
    |
    | If not set, the system will automatically try to find a suitable route:
    | 1. Named 'login' route
    | 2. Any route with 'guest' middleware
    | 3. Fallback to root URL '/'
    |
    | Example: '/login', '/register', '/forgot-password'
    |
    */

    'guest_url' => env('SHIELDCI_GUEST_URL', null),

    /*
    |--------------------------------------------------------------------------
    | Fail Conditions
    |--------------------------------------------------------------------------
    |
    | Define when the analysis should fail (exit code 1).
    |
    */

    'fail_on' => env('SHIELDCI_FAIL_ON', 'critical'), // never, critical, high, medium, low

    'fail_threshold' => env('SHIELDCI_FAIL_THRESHOLD', null), // minimum score to pass (0-100)

];
