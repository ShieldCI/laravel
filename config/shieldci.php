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
    | Environment Mapping
    |--------------------------------------------------------------------------
    |
    | Map custom environment names to standard environment types.
    |
    | Standard environments (no mapping needed):
    | - local: Local development on developer machines
    | - development: Development server environment
    | - staging: Pre-production/staging environment
    | - production: Live production environment
    | - testing: Automated testing environment (PHPUnit, CI/CD)
    |
    | Only configure mappings for custom environment names that don't match
    | the standard names above.
    |
    | Common multi-environment scenarios:
    | - Blue-green deployments: production-blue, production-green
    | - Multi-region: production-us, production-eu, production-asia
    | - Numbered environments: prod-1, prod-2, staging-1
    | - Preview environments: staging-preview, staging-pr-123
    |
    | Example configuration:
    |
    | 'environment_mapping' => [
    |     'production-us' => 'production',
    |     'production-eu' => 'production',
    |     'production-blue' => 'production',
    |     'production-green' => 'production',
    |     'prod-1' => 'production',
    |     'prod-2' => 'production',
    |     'staging-preview' => 'staging',
    |     'staging-1' => 'staging',
    |     'stag-us' => 'staging',
    | ],
    |
    | How it works:
    | - If APP_ENV=production → No mapping needed, uses 'production' directly
    | - If APP_ENV=production-us → Maps to 'production'
    | - If APP_ENV=local → No mapping needed, uses 'local' directly
    | - If APP_ENV=demo → No mapping, uses 'demo' (won't match production/staging)
    |
    | Analyzers then use standard environment names in their $relevantEnvironments:
    |   protected ?array $relevantEnvironments = ['production', 'staging'];
    |
    */

    'environment_mapping' => [
        // Map your custom environment names to standard types here
        // Example:
        // 'production-us' => 'production',
        // 'staging-preview' => 'staging',
    ],

    /*
    |--------------------------------------------------------------------------
    | Analyzer Categories
    |--------------------------------------------------------------------------
    |
    | Enable or disable entire categories of analyzers.
    | Available categories: security, performance, reliability, code_quality, best_practices
    |
    */

    'analyzers' => [
        'security' => [
            'enabled' => env('SHIELDCI_SECURITY_ANALYZERS', true),
        ],
        'performance' => [
            'enabled' => env('SHIELDCI_PERFORMANCE_ANALYZERS', true),
        ],
        'reliability' => [
            'enabled' => env('SHIELDCI_RELIABILITY_ANALYZERS', true),
        ],
        'code_quality' => [
            'enabled' => env('SHIELDCI_CODE_QUALITY_ANALYZERS', true),
        ],
        'best_practices' => [
            'enabled' => env('SHIELDCI_BEST_PRACTICES_ANALYZERS', true),
        ],
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
    | Build Path
    |--------------------------------------------------------------------------
    |
    | The path where compiled assets (JS, CSS) are located for production.
    | Defaults to the public directory.
    |
    */

    'build_path' => env('SHIELDCI_BUILD_PATH', public_path()),

    /*
    |--------------------------------------------------------------------------
    | Writable Directories
    |--------------------------------------------------------------------------
    |
    | Directories that must be writable for the application to function.
    | These paths are relative to the base path of your Laravel application.
    |
    */

    'writable_directories' => [
        'storage',
        'bootstrap/cache',
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

        'show_recommendations' => env('SHIELDCI_SHOW_RECOMMENDATIONS', true),

        'show_code_snippets' => env('SHIELDCI_SHOW_CODE_SNIPPETS', true),

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
