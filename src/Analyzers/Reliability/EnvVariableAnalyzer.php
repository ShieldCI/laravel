<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Concerns\AnalyzesEnvFiles;
use ShieldCI\Concerns\DetectsDeploymentPlatform;

/**
 * Checks that all environment variables from .env.example are defined in .env.
 *
 * Grading is default-aware: a variable that is absent from .env but whose
 * env() call in config/ supplies a real default is the lean-.env style
 * working as intended (config owns defaults, .env owns overrides), so it is
 * reported through result metadata instead of a High issue. Variables with
 * no config default (bare env('KEY') or an explicit null default) stay High:
 * the app reads null when they are unset.
 *
 * Checks for:
 * - .env file exists
 * - Variables from .env.example without a config default are present in .env
 * - Optional (report_defaulted): variables relying on config defaults
 * - Optional (report_redundant): .env values restating the config default
 */
class EnvVariableAnalyzer extends AbstractFileAnalyzer
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
            return 'Laravel Cloud writes a platform-managed .env; missing variables are provided via the Cloud dashboard, not .env.example';
        }

        return 'Vapor removes the plain .env file from the deployment; environment variables are provided via Vapor UI (SSM Parameter Store, plaintext vars, or encrypted environment files)';
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'env-variables-complete',
            name: 'Environment Variables Complete Analyzer',
            description: 'Ensures all required environment variables from .env.example are defined in .env',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['environment', 'configuration', 'reliability', 'deployment'],
            timeToFix: 20
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $basePath = $this->getBasePath();
        $envExamplePath = $this->getEnvExamplePath($basePath);
        $envPath = $this->getEnvPath($basePath);

        // Check if .env.example exists
        if (! file_exists($envExamplePath)) {
            return $this->warning('.env.example file not found - cannot verify environment variables');
        }

        // Check if .env exists
        if (! file_exists($envPath)) {
            return $this->resultBySeverity(
                '.env file not found',
                [$this->createIssue(
                    message: '.env file is missing',
                    location: new Location($this->getRelativePath($envPath)),
                    severity: Severity::Critical,
                    recommendation: $this->buildMissingEnvFileRecommendation(),
                    metadata: ['code' => 'missing-env'],
                )]
            );
        }

        // Parse both files and track errors
        $exampleResult = $this->parseEnvFileWithErrors($envExamplePath);
        $actualResult = $this->parseEnvFileWithErrors($envPath);
        $commentedResult = $this->parseCommentedVariablesWithErrors($envPath);

        // Handle parsing failures
        if ($exampleResult['error'] !== null) {
            return $this->resultBySeverity(
                'Failed to parse .env.example file',
                [$this->createIssue(
                    message: 'Unable to parse .env.example file',
                    location: new Location($this->getRelativePath($envExamplePath)),
                    severity: Severity::Critical,
                    recommendation: sprintf(
                        "The .env.example file could not be parsed. Error: %s\n\nEnsure the file is readable and properly formatted.",
                        $exampleResult['error']
                    ),
                    metadata: ['error' => $exampleResult['error'], 'code' => 'parse-error-example']
                )]
            );
        }

        if ($actualResult['error'] !== null) {
            return $this->resultBySeverity(
                'Failed to parse .env file',
                [$this->createIssue(
                    message: 'Unable to parse .env file',
                    location: new Location($this->getRelativePath($envPath)),
                    severity: Severity::High,
                    recommendation: sprintf(
                        "The .env file could not be parsed. Error: %s\n\nEnsure the file is readable and properly formatted.",
                        $actualResult['error']
                    ),
                    metadata: ['error' => $actualResult['error'], 'code' => 'parse-error-env']
                )]
            );
        }

        $exampleVars = $exampleResult['variables'];
        $actualVars = $actualResult['variables'];
        $commentedVars = $commentedResult['variables'];

        // Find variables that are missing (not active and not commented)
        $missingVars = [];
        $commentedOnlyVars = [];

        foreach ($exampleVars as $key => $value) {
            // Variable is active in .env
            if (isset($actualVars[$key])) {
                continue;
            }

            // Variable is commented out in .env
            if (isset($commentedVars[$key])) {
                $commentedOnlyVars[$key] = $value;

                continue;
            }

            // Variable is completely absent from .env
            $missingVars[$key] = $value;
        }

        $reportDefaulted = (bool) config('shieldci.analyzers.reliability.env-variables-complete.report_defaulted', false);
        $reportRedundant = (bool) config('shieldci.analyzers.reliability.env-variables-complete.report_redundant', false);

        $usages = ($missingVars !== [] || $reportRedundant)
            ? $this->collectConfigEnvKeyUsages()
            : [];

        // Split missing variables by whether config supplies a real default
        $defaultedVars = [];
        $stillMissing = [];

        foreach ($missingVars as $key => $value) {
            if (isset($usages[$key]) && $usages[$key]['hasDefault']) {
                $defaultedVars[$key] = $value;
            } else {
                $stillMissing[$key] = $value;
            }
        }

        $redundantVars = [];

        if ($reportRedundant) {
            foreach ($actualResult['values'] as $key => $value) {
                $default = $usages[$key]['default'] ?? null;

                if ($default !== null && $default === $value) {
                    $redundantVars[] = $key;
                }
            }
        }

        $resultMetadata = [];

        if ($defaultedVars !== []) {
            $resultMetadata = [
                'defaulted_count' => count($defaultedVars),
                'defaulted_variables' => array_keys($defaultedVars),
            ];
        }

        $hasInfoIssues = ($reportDefaulted && $defaultedVars !== []) || $redundantVars !== [];

        // All variables are present, either directly or through config defaults
        if ($stillMissing === [] && $commentedOnlyVars === [] && ! $hasInfoIssues) {
            if ($defaultedVars !== []) {
                return $this->passed(
                    sprintf('All required environment variables are set (%d using config defaults)', count($defaultedVars)),
                    $resultMetadata
                );
            }

            return $this->passed('All environment variables from .env.example are defined and enabled in .env');
        }

        // Only commented variables, no truly missing ones
        if ($stillMissing === [] && $commentedOnlyVars !== [] && ! $hasInfoIssues) {
            return $this->warning(
                sprintf('Found %d commented environment variable(s)', count($commentedOnlyVars)),
                [$this->createIssue(
                    message: 'Environment variables are commented out',
                    location: new Location($this->getRelativePath($envPath)),
                    severity: Severity::Low,
                    recommendation: $this->buildCommentedVariablesRecommendation($commentedOnlyVars),
                    metadata: [
                        'commented_count' => count($commentedOnlyVars),
                        'commented_variables' => array_keys($commentedOnlyVars),
                        'code' => 'commented-variables',
                    ]
                )],
                $resultMetadata
            );
        }

        // Build issues for missing, commented, and opt-in informational groups
        $issues = [];

        if ($stillMissing !== []) {
            $issues[] = $this->createIssue(
                message: 'Missing environment variables',
                location: new Location($this->getRelativePath($envPath)),
                severity: Severity::High,
                recommendation: $this->buildMissingVariablesRecommendation($stillMissing),
                metadata: [
                    'missing_count' => count($stillMissing),
                    'missing_variables' => array_keys($stillMissing),
                    'code' => 'missing-variables',
                ]
            );
        }

        if ($commentedOnlyVars !== []) {
            $issues[] = $this->createIssue(
                message: 'Environment variables are commented out',
                location: new Location($this->getRelativePath($envPath)),
                severity: Severity::Low,
                recommendation: $this->buildCommentedVariablesRecommendation($commentedOnlyVars),
                metadata: [
                    'commented_count' => count($commentedOnlyVars),
                    'commented_variables' => array_keys($commentedOnlyVars),
                    'code' => 'commented-variables',
                ]
            );
        }

        if ($reportDefaulted && $defaultedVars !== []) {
            $issues[] = $this->createIssue(
                message: 'Environment variables relying on config defaults',
                location: new Location($this->getRelativePath($envPath)),
                severity: Severity::Info,
                recommendation: $this->buildDefaultedVariablesRecommendation($defaultedVars),
                metadata: [
                    'defaulted_count' => count($defaultedVars),
                    'defaulted_variables' => array_keys($defaultedVars),
                    'code' => 'defaulted-variables',
                ]
            );
        }

        if ($redundantVars !== []) {
            $issues[] = $this->createIssue(
                message: 'Environment variables restating config defaults',
                location: new Location($this->getRelativePath($envPath)),
                severity: Severity::Info,
                recommendation: $this->buildRedundantVariablesRecommendation($redundantVars),
                metadata: [
                    'redundant_count' => count($redundantVars),
                    'redundant_variables' => $redundantVars,
                    'code' => 'redundant-override',
                ]
            );
        }

        $totalCount = count($stillMissing) + count($commentedOnlyVars)
            + ($reportDefaulted ? count($defaultedVars) : 0)
            + count($redundantVars);

        return $this->resultBySeverity(
            sprintf('Found %d environment variable issue(s)', $totalCount),
            $issues,
            $resultMetadata
        );
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
     * Build recommendation message for missing .env file.
     */
    private function buildMissingEnvFileRecommendation(): string
    {
        return sprintf(
            <<<'RECOMMENDATION'
Create a .env file by copying .env.example.
Unix/Linux:
  %s

Windows:
  %s
After creating the file, configure the environment variables with appropriate values for your environment.
RECOMMENDATION,
            'cp .env.example .env',
            'copy .env.example .env'
        );
    }

    /**
     * Build recommendation message for missing environment variables.
     *
     * @param  array<string, string>  $missingVars
     */
    private function buildMissingVariablesRecommendation(array $missingVars): string
    {
        $missingKeys = array_keys($missingVars);
        $variablesList = implode(', ', $missingKeys);

        return sprintf(
            <<<'RECOMMENDATION'
Add the following environment variables to your .env file: %s
These variables are defined in .env.example and may be required for the application to function correctly.
RECOMMENDATION,
            $variablesList,
        );
    }

    /**
     * Build recommendation message for commented environment variables.
     *
     * @param  array<string, string>  $commentedVars
     */
    private function buildCommentedVariablesRecommendation(array $commentedVars): string
    {
        $commentedKeys = array_keys($commentedVars);
        $variablesList = implode(', ', $commentedKeys);

        return sprintf(
            <<<'RECOMMENDATION'
The following environment variables are commented out in .env: %s
These variables are defined in .env.example. If they're intentionally disabled, this is fine.
If they should be active, uncomment them in your .env file.
RECOMMENDATION,
            $variablesList,
        );
    }

    /**
     * Build recommendation message for variables relying on config defaults.
     *
     * @param  array<string, string>  $defaultedVars
     */
    private function buildDefaultedVariablesRecommendation(array $defaultedVars): string
    {
        $variablesList = implode(', ', array_keys($defaultedVars));

        return sprintf(
            <<<'RECOMMENDATION'
The following environment variables are not set in .env and use the defaults defined in config files: %s
This is the lean .env style working as intended; set a variable in .env only when this environment needs to override its config default.
RECOMMENDATION,
            $variablesList,
        );
    }

    /**
     * Build recommendation message for redundant environment variable overrides.
     *
     * @param  array<int, string>  $redundantVars
     */
    private function buildRedundantVariablesRecommendation(array $redundantVars): string
    {
        $variablesList = implode(', ', $redundantVars);

        return sprintf(
            <<<'RECOMMENDATION'
The following environment variables restate the default already defined in config files: %s
Removing them from .env lets future config default changes take effect without editing every environment.
RECOMMENDATION,
            $variablesList,
        );
    }
}
