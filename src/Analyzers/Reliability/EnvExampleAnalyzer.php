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
 * - every env() key read by the app's own config/ files WITHOUT a real
 *   default must appear in .env.example (actively or commented out).
 *
 * The config direction mirrors the drift analyzer's principle: a key with a
 * real config default is an optional knob that config owns, so documenting
 * it stays voluntary; a bare env('KEY') or explicit null default reads null
 * when unset, making the key a required input worth documenting. Bare keys
 * that any installed package's own vendor config also reads are
 * vendor-owned and exempt; the direction is skipped on Laravel 9/10, which
 * ship no framework config stubs for that comparison.
 *
 * Checks for:
 * - All variables from .env are present in .env.example
 * - env() keys read in config files without a default are documented in .env.example
 * - Ensures .env.example serves as proper documentation
 * - Helps with team onboarding and deployment
 */
class EnvExampleAnalyzer extends AbstractFileAnalyzer
{
    use AnalyzesEnvFiles;
    use DetectsDeploymentPlatform;

    public static bool $runInCI = false;

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
     * Build one Medium issue per env() key read in config/ without a real
     * default that .env.example does not document (actively or commented)
     * and no exemption covers.
     *
     * @param  array<string, string>  $exampleVars
     * @param  array<string, string>  $exampleCommented
     * @return array<int, Issue>
     */
    private function buildUndocumentedConfigKeyIssues(array $exampleVars, array $exampleCommented): array
    {
        // Pre-11 laravel/framework ships no config stubs, so the vendor
        // filter that separates bare stock keys from app keys has no data;
        // skip the config direction there.
        if (! is_dir($this->getBasePath().'/vendor/laravel/framework/config')) {
            return [];
        }

        $usages = $this->collectConfigEnvKeyUsages();

        if ($usages === []) {
            return [];
        }

        $vendorKeys = $this->collectVendorConfigEnvKeys();
        $ignoredKeys = $this->loadIgnoredKeys();

        $issues = [];

        foreach ($usages as $key => $usage) {
            // A real config default makes the key an optional knob that
            // config owns; only defaultless keys require documentation.
            if ($usage['hasDefault']) {
                continue;
            }

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
                    'code' => 'undocumented-config-key',
                ]
            );
        }

        return $issues;
    }

    /**
     * Load the per-project ignored keys.
     *
     * @return array<int, string>
     */
    private function loadIgnoredKeys(): array
    {
        $configured = config('shieldci.analyzers.reliability.env-example-documented.ignored_keys', []);

        if (! is_array($configured)) {
            $configured = [];
        }

        return array_values(array_unique(array_filter($configured, 'is_string')));
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
The %s environment variable is read by a config file without a default, so the application reads null when it is not set.
Add it to .env.example (actively or commented out) so other developers can see it must be configured.
RECOMMENDATION,
            $key,
        );
    }
}
