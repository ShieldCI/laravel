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
    | They will still appear in the report output.
    | Useful for informational checks that shouldn't fail CI/CD.
    |
    | Behavior:
    | - Analyzers run normally and show in report
    | - Issues are displayed in console/JSON output
    | - Exit code is not affected (won't fail CI/CD)
    | - Useful for gradual adoption or informational analyzers
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

        'snippet_context_lines' => env('SHIELDCI_SNIPPET_CONTEXT_LINES', 8), // Lines before/after the issue

        'snippet_plain_mode' => env('SHIELDCI_SNIPPET_PLAIN_MODE', false), // Disable ANSI colors for copy-paste

        'snippet_syntax_highlighting' => env('SHIELDCI_SNIPPET_SYNTAX_HIGHLIGHTING', true), // Enable PHP syntax highlighting

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
    | Behavior:
    | - Filtered issues are completely removed from the report
    | - Does not appear in console/JSON output
    | - Does not affect exit code
    | - Applied before baseline filtering
    |
    | Structure: analyzer_id => array of error definitions (must not be empty)
    |
    | Note: An empty array [] has no effect and will trigger a warning.
    |       Either specify at least one rule or remove the analyzer entry entirely.
    |
    | Each error definition can include:
    | - 'path': Exact file path match (e.g., 'app/Models/User.php')
    | - 'path_pattern': Glob pattern for path matching (e.g., 'app/Legacy/**.php')
    | - 'message': Exact error message match (case-sensitive)
    | - 'message_pattern': Wildcard pattern for message matching (e.g., 'XSS')
    |
    | Important: Do NOT use both 'path' and 'path_pattern' in the same rule.
    |            Do NOT use both 'message' and 'message_pattern' in the same rule.
    |            The system will warn you if you mix them.
    |
    | Matching Rules:
    | - 'path': Exact match only (normalized for Windows/Unix compatibility)
    | - 'path_pattern': Glob pattern using fnmatch (supports wildcards and globstars)
    | - 'message': Exact match only (case-sensitive)
    | - 'message_pattern': Laravel Str::is() wildcards (supports wildcards and character sets)
    | - Both path AND message must match if both are specified
    | - If only path is specified, matches ANY message in that path
    | - If only message is specified, matches ANY path with that message
    |
    | Examples:
    |
    | // Example 1: Ignore exact file and exact message
    | 'ignore_errors' => [
    |     'xss-detection' => [
    |         [
    |             'path' => 'app/Http/Controllers/LegacyController.php',
    |             'message' => 'Potential XSS: Unescaped blade output',
    |         ],
    |     ],
    | ],
    |
    | // Example 2: Ignore all issues in legacy directory (using path pattern)
    | 'ignore_errors' => [
    |     'xss-detection' => [
    |         ['path_pattern' => 'app/Legacy/*.php'],
    |     ],
    | ],
    |
    | // Example 3: Ignore all issues in a specific file (any message)
    | 'ignore_errors' => [
    |     'sql-injection' => [
    |         ['path' => 'app/Models/OldModel.php'],
    |     ],
    | ],
    |
    | // Example 4: Ignore specific message across all files (using message pattern)
    | 'ignore_errors' => [
    |     'debug-mode' => [
    |         ['message_pattern' => 'Ray debugging*'],
    |     ],
    | ],
    |
    | // Example 5: Multiple rules for same analyzer
    | 'ignore_errors' => [
    |     'xss-detection' => [
    |         ['path_pattern' => 'app/Legacy/*.php'],
    |         ['path_pattern' => 'app/Admin/Old*.php'],
    |         ['message' => 'Known safe usage in template'],
    |     ],
    | ],
    |
    | // Example 6: Glob pattern examples (recursive with globstar)
    | 'ignore_errors' => [
    |     'code-quality' => [
    |         ['path_pattern' => 'tests/*.php'],                   // All PHP files directly in tests
    |         ['path_pattern' => 'app/Legacy/*.php'],              // Only PHP files directly in app/Legacy
    |         ['path_pattern' => 'database/migrations/*.php'],     // All migration files
    |     ],
    | ],
    |
    */

    'ignore_errors' => [],

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
