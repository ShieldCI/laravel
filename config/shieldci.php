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

        'output_file' => storage_path('shieldci-report.json'),

        'show_recommendations' => true,

        'show_code_snippets' => true,
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
