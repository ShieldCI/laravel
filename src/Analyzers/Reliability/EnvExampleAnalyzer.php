<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Concerns\AnalyzesEnvFiles;
use ShieldCI\Concerns\DetectsDeploymentPlatform;

/**
 * Checks that .env.example documents the environment variables the
 * application can use.
 *
 * Two directions feed the same documentation goal:
 * - every variable set in .env must appear in .env.example, and
 * - every env() key read by the app's own config/ files must appear in
 *   .env.example (actively or commented out).
 *
 * Framework- and vendor-owned keys are exempt from the config direction:
 * keys read by any installed package's own vendor config are recognized by
 * provenance, and stock laravel/laravel skeleton keys by a built-in list.
 *
 * Checks for:
 * - All variables from .env are present in .env.example
 * - env() keys read in config files are documented in .env.example
 * - Ensures .env.example serves as proper documentation
 * - Helps with team onboarding and deployment
 */
class EnvExampleAnalyzer extends AbstractFileAnalyzer
{
    use AnalyzesEnvFiles;
    use DetectsDeploymentPlatform;

    public static bool $runInCI = false;

    /**
     * Every config env() key across laravel/laravel skeleton branches
     * 9.x-13.x. Framework-owned keys are not the application's
     * documentation debt, and on Laravel 9/10 the framework ships no
     * vendor config stubs for the provenance check to find.
     *
     * Regenerate by fetching each skeleton config file from GitHub,
     * flattening newlines (multi-line env() calls are real), and taking
     * the sorted unique key set of:
     * grep -oE "env\([[:space:]]*'[A-Za-z0-9_]+'"
     */
    private const BUILTIN_IGNORED_KEYS = [
        'ABLY_KEY',
        'APP_DEBUG',
        'APP_ENV',
        'APP_FAKER_LOCALE',
        'APP_FALLBACK_LOCALE',
        'APP_KEY',
        'APP_LOCALE',
        'APP_MAINTENANCE_DRIVER',
        'APP_MAINTENANCE_STORE',
        'APP_NAME',
        'APP_PREVIOUS_KEYS',
        'APP_URL',
        'ASSET_URL',
        'AUTH_GUARD',
        'AUTH_MODEL',
        'AUTH_PASSWORD_BROKER',
        'AUTH_PASSWORD_RESET_TOKEN_TABLE',
        'AUTH_PASSWORD_TIMEOUT',
        'AWS_ACCESS_KEY_ID',
        'AWS_BUCKET',
        'AWS_DEFAULT_REGION',
        'AWS_ENDPOINT',
        'AWS_SECRET_ACCESS_KEY',
        'AWS_URL',
        'AWS_USE_PATH_STYLE_ENDPOINT',
        'BCRYPT_ROUNDS',
        'BEANSTALKD_QUEUE',
        'BEANSTALKD_QUEUE_HOST',
        'BEANSTALKD_QUEUE_RETRY_AFTER',
        'BROADCAST_DRIVER',
        'CACHE_DRIVER',
        'CACHE_PREFIX',
        'CACHE_STORAGE_DISK',
        'CACHE_STORAGE_PATH',
        'CACHE_STORE',
        'DATABASE_URL',
        'DB_CACHE_CONNECTION',
        'DB_CACHE_LOCK_CONNECTION',
        'DB_CACHE_LOCK_TABLE',
        'DB_CACHE_TABLE',
        'DB_CHARSET',
        'DB_COLLATION',
        'DB_CONNECTION',
        'DB_DATABASE',
        'DB_ENCRYPT',
        'DB_FOREIGN_KEYS',
        'DB_HOST',
        'DB_PASSWORD',
        'DB_PORT',
        'DB_QUEUE',
        'DB_QUEUE_CONNECTION',
        'DB_QUEUE_RETRY_AFTER',
        'DB_QUEUE_TABLE',
        'DB_SOCKET',
        'DB_SSLMODE',
        'DB_TRUST_SERVER_CERTIFICATE',
        'DB_URL',
        'DB_USERNAME',
        'DYNAMODB_CACHE_TABLE',
        'DYNAMODB_ENDPOINT',
        'FILESYSTEM_DISK',
        'LOG_CHANNEL',
        'LOG_DAILY_DAYS',
        'LOG_DEPRECATIONS_CHANNEL',
        'LOG_DEPRECATIONS_TRACE',
        'LOG_LEVEL',
        'LOG_PAPERTRAIL_HANDLER',
        'LOG_SLACK_EMOJI',
        'LOG_SLACK_USERNAME',
        'LOG_SLACK_WEBHOOK_URL',
        'LOG_STACK',
        'LOG_STDERR_FORMATTER',
        'LOG_SYSLOG_FACILITY',
        'MAILGUN_DOMAIN',
        'MAILGUN_ENDPOINT',
        'MAILGUN_SECRET',
        'MAIL_EHLO_DOMAIN',
        'MAIL_ENCRYPTION',
        'MAIL_FROM_ADDRESS',
        'MAIL_FROM_NAME',
        'MAIL_HOST',
        'MAIL_LOG_CHANNEL',
        'MAIL_MAILER',
        'MAIL_PASSWORD',
        'MAIL_PORT',
        'MAIL_SCHEME',
        'MAIL_SENDMAIL_PATH',
        'MAIL_URL',
        'MAIL_USERNAME',
        'MEMCACHED_HOST',
        'MEMCACHED_PASSWORD',
        'MEMCACHED_PERSISTENT_ID',
        'MEMCACHED_PORT',
        'MEMCACHED_USERNAME',
        'MYSQL_ATTR_SSL_CA',
        'PAPERTRAIL_PORT',
        'PAPERTRAIL_URL',
        'POSTMARK_API_KEY',
        'POSTMARK_MESSAGE_STREAM_ID',
        'POSTMARK_TOKEN',
        'PUSHER_APP_CLUSTER',
        'PUSHER_APP_ID',
        'PUSHER_APP_KEY',
        'PUSHER_APP_SECRET',
        'PUSHER_HOST',
        'PUSHER_PORT',
        'PUSHER_SCHEME',
        'QUEUE_CONNECTION',
        'QUEUE_FAILED_DRIVER',
        'REDIS_BACKOFF_ALGORITHM',
        'REDIS_BACKOFF_BASE',
        'REDIS_BACKOFF_CAP',
        'REDIS_CACHE_CONNECTION',
        'REDIS_CACHE_DB',
        'REDIS_CACHE_LOCK_CONNECTION',
        'REDIS_CLIENT',
        'REDIS_CLUSTER',
        'REDIS_DB',
        'REDIS_HOST',
        'REDIS_MAX_RETRIES',
        'REDIS_PASSWORD',
        'REDIS_PERSISTENT',
        'REDIS_PORT',
        'REDIS_PREFIX',
        'REDIS_QUEUE',
        'REDIS_QUEUE_CONNECTION',
        'REDIS_QUEUE_RETRY_AFTER',
        'REDIS_URL',
        'REDIS_USERNAME',
        'RESEND_API_KEY',
        'RESEND_KEY',
        'SANCTUM_STATEFUL_DOMAINS',
        'SANCTUM_TOKEN_PREFIX',
        'SESSION_CONNECTION',
        'SESSION_COOKIE',
        'SESSION_DOMAIN',
        'SESSION_DRIVER',
        'SESSION_ENCRYPT',
        'SESSION_EXPIRE_ON_CLOSE',
        'SESSION_HTTP_ONLY',
        'SESSION_LIFETIME',
        'SESSION_PARTITIONED_COOKIE',
        'SESSION_PATH',
        'SESSION_SAME_SITE',
        'SESSION_SECURE_COOKIE',
        'SESSION_STORE',
        'SESSION_TABLE',
        'SLACK_BOT_USER_DEFAULT_CHANNEL',
        'SLACK_BOT_USER_OAUTH_TOKEN',
        'SQS_PREFIX',
        'SQS_QUEUE',
        'SQS_SUFFIX',
        'VIEW_COMPILED_PATH',
    ];

    public function shouldRun(): bool
    {
        return ! $this->isVaporOrServerless() && ! $this->isLaravelCloud();
    }

    public function getSkipReason(): string
    {
        if ($this->isLaravelCloud()) {
            return 'Laravel Cloud injects environment variables (NIGHTWATCH_*, LOG_*, REDIS_*, etc.) directly into the container — these are platform-managed and should not be documented in .env.example';
        }

        return 'Vapor removes .env and .env.example from the deployment; environment variables are provided via Vapor UI (SSM Parameter Store, plaintext vars, or encrypted environment files)';
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'env-example-documented',
            name: 'Environment Example Documentation Analyzer',
            description: 'Ensures all environment variables used in .env and read by config files are documented in .env.example',
            category: Category::Reliability,
            severity: Severity::Low,
            tags: ['environment', 'configuration', 'documentation', 'team-collaboration'],
            timeToFix: 10
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $basePath = $this->getBasePath();
        $envPath = $this->getEnvPath($basePath);
        $envExamplePath = $this->getEnvExamplePath($basePath);

        // With neither file present there is nothing to verify in either
        // direction; matches the pre-config-direction behavior.
        if (! file_exists($envPath) && ! file_exists($envExamplePath)) {
            return $this->warning('.env file not found - cannot verify documentation');
        }

        // Check if .env.example exists
        if (! file_exists($envExamplePath)) {
            return $this->resultBySeverity(
                '.env.example file not found',
                [$this->createIssue(
                    message: '.env.example file is missing',
                    location: new Location('.env.example'),
                    severity: Severity::High,
                    recommendation: $this->buildMissingExampleFileRecommendation(),
                    metadata: []
                )]
            );
        }

        $exampleResult = $this->parseEnvFileWithErrors($envExamplePath);
        $exampleVars = $exampleResult['error'] === null ? $exampleResult['variables'] : [];
        $exampleCommented = $this->parseCommentedVariablesWithErrors($envExamplePath)['variables'];

        // Config direction: env() keys read in config/ but not documented.
        // Runs regardless of .env presence — it only needs code and .env.example.
        $configIssues = $this->buildUndocumentedConfigKeyIssues($exampleVars, $exampleCommented);

        // The .env direction needs an actual .env file
        if (! file_exists($envPath)) {
            if ($configIssues === []) {
                return $this->warning('.env file not found - cannot verify documentation');
            }

            return $this->resultBySeverity(
                sprintf('Found %d undocumented environment variable(s)', count($configIssues)),
                $configIssues
            );
        }

        $envResult = $this->parseEnvFileWithErrors($envPath);
        $envVars = $envResult['error'] === null ? $envResult['variables'] : [];

        // Find undocumented variables (in .env but not in .env.example)
        $undocumentedVars = array_diff_key($envVars, $exampleVars);

        $issues = $configIssues;

        if (! empty($undocumentedVars)) {
            $issues[] = $this->createIssueWithSnippet(
                message: 'Undocumented environment variables',
                filePath: $envExamplePath,
                lineNumber: null,
                severity: Severity::Low,
                recommendation: $this->buildUndocumentedVariablesRecommendation($undocumentedVars),
                column: null,
                contextLines: null,
                metadata: [
                    'undocumented_count' => count($undocumentedVars),
                    'undocumented_variables' => array_keys($undocumentedVars),
                    'code' => 'undocumented-variables',
                ]
            );
        }

        if ($issues === []) {
            return $this->passed('All environment variables are documented in .env.example');
        }

        $totalCount = count($configIssues) + count($undocumentedVars);

        return $this->resultBySeverity(
            sprintf('Found %d undocumented environment variable(s)', $totalCount),
            $issues
        );
    }

    /**
     * Build one Medium issue per env() key read in config/ that .env.example
     * does not document (actively or commented) and no exemption covers.
     *
     * @param  array<string, string>  $exampleVars
     * @param  array<string, string>  $exampleCommented
     * @return array<int, Issue>
     */
    private function buildUndocumentedConfigKeyIssues(array $exampleVars, array $exampleCommented): array
    {
        $usages = $this->collectConfigEnvKeyUsages();

        if ($usages === []) {
            return [];
        }

        $vendorKeys = $this->collectVendorConfigEnvKeys();
        $ignoredKeys = $this->loadIgnoredKeys();

        $issues = [];

        foreach ($usages as $key => $usage) {
            if (isset($exampleVars[$key]) || isset($exampleCommented[$key]) || isset($vendorKeys[$key])) {
                continue;
            }

            if ($this->isIgnoredKey($key, $ignoredKeys)) {
                continue;
            }

            $issues[] = $this->createIssueWithSnippet(
                message: sprintf("Environment variable '%s' is read in config files but not documented in .env.example", $key),
                filePath: $usage['file'],
                lineNumber: $usage['line'],
                severity: Severity::Medium,
                recommendation: $this->buildUndocumentedConfigKeyRecommendation($key),
                metadata: [
                    'key' => $key,
                    'has_config_default' => $usage['hasDefault'],
                    'code' => 'undocumented-config-key',
                ]
            );
        }

        return $issues;
    }

    /**
     * Merge the built-in framework key list with per-project ignores.
     *
     * @return array<int, string>
     */
    private function loadIgnoredKeys(): array
    {
        $configured = config('shieldci.analyzers.reliability.env-example-documented.ignored_keys', []);

        if (! is_array($configured)) {
            $configured = [];
        }

        return array_values(array_unique(array_merge(
            self::BUILTIN_IGNORED_KEYS,
            array_filter($configured, 'is_string')
        )));
    }

    /**
     * @param  array<int, string>  $ignoredKeys
     */
    private function isIgnoredKey(string $key, array $ignoredKeys): bool
    {
        foreach ($ignoredKeys as $pattern) {
            if ($pattern === $key) {
                return true;
            }

            if (str_contains($pattern, '*') && fnmatch($pattern, $key)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get the .env file path.
     */
    private function getEnvPath(string $basePath): string
    {
        if ($basePath === '') {
            return '.env';
        }

        return rtrim($basePath, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.'.env';
    }

    /**
     * Get the .env.example file path.
     */
    private function getEnvExamplePath(string $basePath): string
    {
        if ($basePath === '') {
            return '.env.example';
        }

        return rtrim($basePath, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.'.env.example';
    }

    /**
     * Build recommendation message for missing .env.example file.
     */
    private function buildMissingExampleFileRecommendation(): string
    {
        return <<<'RECOMMENDATION'
Create a .env.example file to document all environment variables used in your application.
RECOMMENDATION;
    }

    /**
     * Build recommendation message for undocumented variables.
     *
     * @param  array<string, string>  $undocumentedVars
     */
    private function buildUndocumentedVariablesRecommendation(array $undocumentedVars): string
    {
        $undocumentedKeys = array_keys($undocumentedVars);
        $variablesList = implode(', ', $undocumentedKeys);

        return sprintf(
            <<<'RECOMMENDATION'
Add the following environment variables to your .env.example file: %s
These variables are currently used in .env but not documented in .env.example.
This makes it harder for team members to know what variables are required.
RECOMMENDATION,
            $variablesList,
        );
    }

    /**
     * Build recommendation message for a config-read key missing from .env.example.
     */
    private function buildUndocumentedConfigKeyRecommendation(string $key): string
    {
        return sprintf(
            <<<'RECOMMENDATION'
The %s environment variable is read by a config file but does not appear in .env.example.
Add it to .env.example (actively or commented out) so other developers can see it is available for configuration.
RECOMMENDATION,
            $key,
        );
    }
}
