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
    | ShieldCI Platform Integration
    |--------------------------------------------------------------------------
    |
    | Connect to the ShieldCI platform for centralized dashboards, historical
    | trends, and team-wide visibility. Sign up at https://shieldci.com
    |
    | These settings are optional. The package works fully offline without
    | any platform credentials configured.
    |
    */

    'token' => env('SHIELDCI_TOKEN'),

    'project_id' => env('SHIELDCI_PROJECT_ID'),

    'api_url' => env('SHIELDCI_API_URL', 'https://shieldci.com'),

    /*
    |--------------------------------------------------------------------------
    | Documentation Base URL
    |--------------------------------------------------------------------------
    |
    | Base URL for analyzer documentation
    |
    | URLs are auto-generated as: {base_url}/analyzers/{category}/{analyzer-id}
    | Example: https://docs.shieldci.com/analyzers/security/sql-injection
    |
    */

    'docs_base_url' => env('SHIELDCI_DOCS_URL', 'https://docs.shieldci.com'),

    /*
    |--------------------------------------------------------------------------
    | Guest URL
    |--------------------------------------------------------------------------
    |
    | Override the guest/login URL used by authentication-related analyzers.
    | By default, the analyzers auto-detect common login routes.
    |
    */

    'guest_url' => env('SHIELDCI_GUEST_URL'),

    /*
    |--------------------------------------------------------------------------
    | Security Advisories
    |--------------------------------------------------------------------------
    |
    | Configure the source for PHP security advisory data.
    |
    */

    'security_advisories' => [
        'source' => env('SHIELDCI_ADVISORY_SOURCE', 'https://api.osv.dev/v1/querybatch'),

        // Endpoint used to resolve full vulnerability details (CVE, links, real
        // affected ranges) by id, since the batch "source" returns only ids.
        // Defaults to deriving "/vulns" from the "source" URL when left null.
        'vulns_source' => env('SHIELDCI_ADVISORY_VULNS_SOURCE'),
    ],

    /*
    |--------------------------------------------------------------------------
    | CI Mode Configuration
    |--------------------------------------------------------------------------
    |
    | Configure ShieldCI behavior in CI/CD environments.
    | Activate CI mode via the --ci flag: php artisan shield:analyze --ci
    |
    */

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
    | Map custom environment names onto the standard ones, which analyzers match
    | against in their $relevantEnvironments.
    |
    | Standard: local, development, staging, production, testing. Names matching
    | one of these need no entry, and an unmapped name is used as-is, so it will
    | not match production or staging rules.
    |
    | Useful for blue-green, multi-region, numbered and preview environments:
    |
    | 'environment_mapping' => [
    |     'production-eu' => 'production',
    |     'prod-1' => 'production',
    |     'staging-pr-123' => 'staging',
    | ],
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
    | Available categories: security, performance, reliability, code-quality, best-practices
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
        'code-quality' => [
            'enabled' => env('SHIELDCI_CODE_QUALITY_ANALYZERS', true),
        ],
        'best-practices' => [
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
    | Analyzers listed here run and appear in the report, but do not affect the
    | exit code or the score compared against fail_threshold. Useful for gradual
    | adoption and informational checks.
    |
    | 'php artisan shield:baseline' adds analyzers that fail without naming a
    | specific issue, and merges that list with this one under --baseline.
    | Analyzers that could not run are never added, and are waived here only.
    |
    */

    'dont_report' => [
        // 'missing-error-tracking',
        // 'helper-function-abuse',
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

        'send_to_api' => env('SHIELDCI_SEND_TO_API', false),
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
    | Matching issues are removed from the report entirely, so unlike dont_report
    | they do not appear in console or JSON output. Applied before the baseline.
    |
    | Structure: analyzer_id => list of rules. An empty list has no effect and
    | warns; remove the entry instead.
    |
    | Each rule takes a path and/or a message, in exact or pattern form:
    | - 'path'            exact path, normalised for Windows and Unix
    | - 'path_pattern'    glob, via fnmatch
    | - 'message'         exact, case-sensitive
    | - 'message_pattern' wildcards, via Laravel's Str::is()
    |
    | Do not combine 'path' with 'path_pattern', or 'message' with
    | 'message_pattern', in one rule; the run warns if you do. Given both a path
    | and a message, both must match. Given one, it matches any value of the other.
    |
    | 'ignore_errors' => [
    |     'xss-detection' => [
    |         ['path' => 'app/Http/Controllers/Legacy.php', 'message' => 'Unescaped blade output'],
    |         ['path_pattern' => 'app/Legacy/*.php'],
    |     ],
    |     'debug-mode' => [
    |         ['message_pattern' => 'Ray debugging*'],
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
    | fail_on: Severity threshold for build failure
    |   - 'never': Never fail (reporting only)
    |   - 'critical': Fail on Critical issues only (use for legacy codebases)
    |   - 'high': Fail on High or Critical issues (default, recommended)
    |   - 'medium': Fail on Medium, High, or Critical issues
    |   - 'low': Fail on any issues (strict quality enforcement)
    |   - anything else falls back to 'high', and the run says so
    |
    | A non-passing result with no issues carries no severity to compare, so it
    | fails at every level except 'never' ('low' and 'medium' only for a warning).
    | Waive one via 'dont_report' above.
    |
    | fail_threshold: Minimum score to pass (0-100, optional)
    |   - e.g. 80 requires an 80% pass rate
    |   - both fail_on and fail_threshold must pass for exit code 0
    |
    */

    'fail_on' => env('SHIELDCI_FAIL_ON', 'high'),

    'fail_threshold' => env('SHIELDCI_FAIL_THRESHOLD', null),

];
