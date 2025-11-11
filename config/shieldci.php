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
    | Environment-Specific Analyzers
    |--------------------------------------------------------------------------
    |
    | Skip environment-specific analyzers when set to true.
    | Useful for forcing all analyzers to run regardless of environment.
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
        ],
    ],

    'excluded_paths' => [
        'vendor/*',
        'node_modules/*',
        'storage/*',
        'bootstrap/cache/*',
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

        'output_file' => null, // Only save when explicitly requested via --output

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

    'ignore_errors' => [
        // Populated by php artisan shield:baseline or manually configured
        // Example:
        // 'sql-injection' => [
        //     ['path' => 'app/Legacy/*', 'pattern' => '*'],
        // ],
    ],
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
