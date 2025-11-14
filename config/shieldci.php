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
    | This can be manually configured here, or auto-populated by running
    | 'php artisan shield:baseline'. Analyzers that fail but have no
    | specific issues will be automatically added to the baseline's
    | 'dont_report' array.
    |
    | When using --baseline flag, the baseline file's 'dont_report' will
    | be merged with this config value.
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
    | Writable Directories
    |--------------------------------------------------------------------------
    |
    | Directories that must be writable for the application to function.
    | Uses Laravel helper functions for path resolution.
    |
    */

    'writable_directories' => [
        storage_path(),
        base_path('bootstrap/cache'),
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
    | The baseline file supports two types of matching:
    | 1. Hash-based (exact match): Most precise, no false positives
    | 2. Pattern-based (flexible): Supports wildcards for paths and messages
    |
    | Example pattern entry in baseline JSON:
    | "path_pattern": "app/Legacy/*.php" (glob patterns)
    | "message_pattern": "*XSS*" (Laravel Str::is patterns)
    |
    | The baseline also auto-populates 'dont_report' for analyzers that
    | fail but have no specific issues (informational analyzers).
    |
    */

    'baseline_file' => base_path('.shieldci-baseline.json'),

    /*
    |--------------------------------------------------------------------------
    | Ignoring Errors
    |--------------------------------------------------------------------------
    |
    | Manually ignore specific errors by analyzer ID, path, and message.
    | This works alongside the baseline file and is always applied.
    |
    | Structure: analyzer_id => array of error definitions
    |
    | Each error definition can include:
    | - 'path': Exact file path or glob pattern (e.g., 'app/Legacy/*.php')
    | - 'path_pattern': Explicit glob pattern for path matching
    | - 'message': Exact error message or pattern (e.g., '*XSS*')
    | - 'message_pattern': Explicit pattern for message matching (Laravel Str::is)
    |
    | Examples:
    |
    | // Ignore specific file and message
    | 'ignore_errors' => [
    |     'xss-detection' => [
    |         [
    |             'path' => 'app/Http/Controllers/LegacyController.php',
    |             'message' => 'Potential XSS: Unescaped blade output',
    |         ],
    |     ],
    | ],
    |
    | // Ignore all XSS issues in legacy directory
    | 'ignore_errors' => [
    |     'xss-detection' => [
    |         [
    |             'path_pattern' => 'app/Legacy/*.php',
    |             'message_pattern' => '*XSS*',
    |         ],
    |     ],
    | ],
    |
    | // Ignore all issues in a specific file
    | 'ignore_errors' => [
    |     'sql-injection' => [
    |         ['path' => 'app/Models/OldModel.php'],
    |     ],
    | ],
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
