<?php

return [

    /*
    |--------------------------------------------------------------------------
    | ShieldCI API Configuration
    |--------------------------------------------------------------------------
    */

    'enabled' => env('SHIELDCI_ENABLED', true),

    'token' => env('SHIELDCI_TOKEN'),

    'project_id' => env('SHIELDCI_PROJECT_ID'),

    'api_url' => env('SHIELDCI_API_URL', 'https://api.shieldci.com'),

    /*
    |--------------------------------------------------------------------------
    | Analysis Configuration
    |--------------------------------------------------------------------------
    */

    'timeout' => env('SHIELDCI_TIMEOUT', 300), // 5 minutes

    'memory_limit' => env('SHIELDCI_MEMORY_LIMIT', '512M'),

    /*
    |--------------------------------------------------------------------------
    | Analyzer Configuration
    |--------------------------------------------------------------------------
    */

    'analyzers' => [
        'security' => true,
        'performance' => true,
        'code_quality' => true,
        'best_practices' => true,
    ],

    'disabled_analyzers' => [
        // 'sql-injection-detector',
    ],

    'disabled_categories' => [
        // 'performance',
    ],

    /*
    |--------------------------------------------------------------------------
    | Paths Configuration
    |--------------------------------------------------------------------------
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
        '*/migrations/*',
        '*/seeds/*',
        '*/factories/*',
    ],

    /*
    |--------------------------------------------------------------------------
    | Reporting Configuration
    |--------------------------------------------------------------------------
    */

    'report' => [
        'format' => env('SHIELDCI_REPORT_FORMAT', 'console'), // console, json

        'output_file' => storage_path('shieldci-report.json'),

        'send_to_api' => env('SHIELDCI_SEND_TO_API', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Fail Conditions
    |--------------------------------------------------------------------------
    */

    'fail_on' => env('SHIELDCI_FAIL_ON', 'critical'), // never, critical, high, medium, low

    'fail_threshold' => env('SHIELDCI_FAIL_THRESHOLD', null), // minimum score to pass

    /*
    |--------------------------------------------------------------------------
    | Security Analyzer Settings
    |--------------------------------------------------------------------------
    */

    'security' => [
        'sql_injection' => [
            'enabled' => true,
            'check_raw_queries' => true,
            'check_where_raw' => true,
        ],

        'xss' => [
            'enabled' => true,
            'check_blade' => true,
            'check_responses' => true,
        ],

        'csrf' => [
            'enabled' => true,
            'except' => [], // Routes to exclude from CSRF check
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Performance Analyzer Settings
    |--------------------------------------------------------------------------
    */

    'performance' => [
        'n_plus_one' => [
            'enabled' => true,
            'threshold' => 10, // Maximum acceptable queries in loop
        ],

        'cache' => [
            'enabled' => true,
            'check_routes' => true,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Code Quality Analyzer Settings
    |--------------------------------------------------------------------------
    */

    'code_quality' => [
        'complexity' => [
            'enabled' => true,
            'max_complexity' => 10,
        ],

        'psr' => [
            'enabled' => true,
            'standard' => 'PSR-12',
        ],
    ],

];
