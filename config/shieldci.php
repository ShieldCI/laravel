<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Analysis Configuration
    |--------------------------------------------------------------------------
    */

    'enabled' => env('SHIELDCI_ENABLED', true),

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
        'reliability' => true,
        'code_quality' => true,
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
        // Complexity & Size Analyzers
        'cyclomatic_complexity' => [
            'enabled' => true,
            'threshold' => 10, // Maximum cyclomatic complexity per method
        ],

        'cognitive_complexity' => [
            'enabled' => true,
            'threshold' => 15, // Maximum cognitive complexity per method
        ],

        'nesting_depth' => [
            'enabled' => true,
            'max_depth' => 4, // Maximum nesting levels
        ],

        'class_length' => [
            'enabled' => true,
            'max_lines' => 500, // Maximum lines per class
        ],

        'method_length' => [
            'enabled' => true,
            'max_lines' => 50, // Maximum lines per method
        ],

        'parameter_count' => [
            'enabled' => true,
            'max_parameters' => 5, // Maximum parameters per method
        ],

        // Code Duplication
        'duplicate_code' => [
            'enabled' => true,
            'min_lines' => 6, // Minimum lines to consider duplication
            'similarity_threshold' => 85.0, // Similarity percentage (0-100)
        ],

        // Naming Conventions
        'naming_convention' => [
            'enabled' => true,
            'enforce_psr' => true, // Enforce PSR naming standards
        ],

        'inconsistent_naming' => [
            'enabled' => true,
            'allow_mixed_case' => false, // Allow snake_case and camelCase mixing
        ],

        // Maintainability
        'magic_number' => [
            'enabled' => true,
            'excluded_numbers' => [0, 1, -1, 2, 10, 100, 1000], // Numbers to exclude from detection
        ],

        'missing_docblock' => [
            'enabled' => true,
            'require_tags' => true, // Require @param and @return tags
        ],

        'commented_code' => [
            'enabled' => true,
            'min_lines' => 3, // Minimum commented lines to flag
        ],

        'todo_comment' => [
            'enabled' => true,
            'keywords' => ['TODO', 'FIXME', 'HACK', 'XXX', 'BUG'], // Keywords to detect
        ],

        // Laravel Best Practices
        'eloquent_n_plus_one' => [
            'enabled' => true,
            'detect_eager_loading' => true, // Track with() calls
        ],

        'facade_usage' => [
            'enabled' => true,
            'allowed_facades' => [], // Facades to allow (empty = all flagged)
        ],

        'helper_function_abuse' => [
            'enabled' => true,
            'threshold' => 5, // Max helper calls per method
        ],

        'query_builder_in_controller' => [
            'enabled' => true,
            'allowed_methods' => [], // Controller methods to exclude
        ],

        'service_container_resolution' => [
            'enabled' => true,
            'allowed_in' => [], // Locations where app()/resolve() is allowed
        ],

        'complex_conditional' => [
            'enabled' => true,
            'max_operators' => 3, // Maximum logical operators per condition
        ],
    ],

];
