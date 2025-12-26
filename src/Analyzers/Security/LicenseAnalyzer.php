<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Security;

use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\FileParser;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;

/**
 * Validates that dependencies use legally acceptable licenses.
 *
 * Checks for:
 * - GPL/AGPL licenses in commercial applications
 * - Packages with restrictive licenses
 * - Missing license information
 * - Configurable license whitelist
 */
class LicenseAnalyzer extends AbstractFileAnalyzer
{
    /**
     * Default whitelisted licenses for commercial/proprietary use.
     */
    private array $whitelistedLicenses = [
        'Apache-2.0',
        'Apache2',
        'BSD-2-Clause',
        'BSD-3-Clause',
        'LGPL-2.1-only',
        'LGPL-2.1',
        'LGPL-2.1-or-later',
        'LGPL-3.0',
        'LGPL-3.0-only',
        'LGPL-3.0-or-later',
        'MIT',
        'ISC',
        'CC0-1.0',
        'Unlicense',
        'WTFPL',
    ];

    /**
     * Restrictive licenses that require scrutiny.
     */
    private array $restrictiveLicenses = [
        'GPL-2.0',
        'GPL-2.0-only',
        'GPL-2.0-or-later',
        'GPL-3.0',
        'GPL-3.0-only',
        'GPL-3.0-or-later',
        'AGPL-3.0',
        'AGPL-3.0-only',
        'AGPL-3.0-or-later',
    ];

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'license-compliance',
            name: 'Dependency License Compliance Analyzer',
            description: 'Validates that all dependencies use legally acceptable licenses for your application type',
            category: Category::Security,
            severity: Severity::High,
            tags: ['licenses', 'legal', 'compliance', 'dependencies', 'gpl', 'commercial'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/license-compliance',
            timeToFix: 120
        );
    }

    public function shouldRun(): bool
    {
        $composerLock = $this->getBasePath().DIRECTORY_SEPARATOR.'composer.lock';

        return file_exists($composerLock);
    }

    public function getSkipReason(): string
    {
        return 'No composer.lock file found';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check composer.lock for PHP dependencies
        $composerLock = $this->getBasePath().DIRECTORY_SEPARATOR.'composer.lock';

        $this->checkComposerLicenses($composerLock, $issues);

        $summary = empty($issues)
            ? 'All dependency licenses are acceptable'
            : sprintf('Found %d package%s with potentially problematic licenses', count($issues), count($issues) === 1 ? '' : 's');

        return $this->resultBySeverity($summary, $issues);
    }

    /**
     * Check licenses in composer.lock.
     */
    private function checkComposerLicenses(string $composerLock, array &$issues): void
    {
        $content = FileParser::readFile($composerLock);
        if ($content === null) {
            return;
        }

        $lockData = json_decode($content, true);

        if (json_last_error() !== JSON_ERROR_NONE || ! is_array($lockData)) {
            return;
        }

        if (! isset($lockData['packages']) || ! is_array($lockData['packages'])) {
            return;
        }

        $config = $this->getConfiguration();

        // Check production dependencies
        $this->checkPackageLicenses(
            $lockData['packages'],
            $composerLock,
            $issues,
            $config,
            false
        );

        // Check dev dependencies separately (less critical)
        if (isset($lockData['packages-dev']) && is_array($lockData['packages-dev'])) {
            $this->checkPackageLicenses(
                $lockData['packages-dev'],
                $composerLock,
                $issues,
                $config,
                true
            );
        }
    }

    /**
     * Check licenses for a list of packages.
     *
     * @param  array<int, mixed>  $packages
     * @param  array<string, mixed>  $config
     */
    private function checkPackageLicenses(
        array $packages,
        string $composerLock,
        array &$issues,
        array $config,
        bool $isDevDependency
    ): void {
        foreach ($packages as $package) {
            if (! is_array($package)) {
                continue;
            }

            $packageName = isset($package['name']) && is_string($package['name'])
                ? $package['name']
                : 'Unknown';

            // Normalize license to array (handle both string and array)
            $licenses = $this->normalizeLicenseField($package);

            // Skip if no license information
            if (empty($licenses)) {
                // Only flag missing licenses for production dependencies
                if (! $isDevDependency) {
                    $issues[] = $this->createIssue(
                        message: sprintf('Package "%s" has no license information', $packageName),
                        location: new Location($composerLock),
                        severity: Severity::Medium,
                        recommendation: sprintf('Investigate license for "%s" or contact the package maintainer', $packageName),
                        code: FileParser::getCodeSnippet($composerLock, 1),
                        metadata: [
                            'package' => $packageName,
                            'issue_type' => 'missing_license',
                        ]
                    );
                }

                continue;
            }

            // Normalize licenses to uppercase for comparison
            $normalizedLicenses = array_map('strtoupper', $licenses);

            /** @var array<int, string> $whitelistedLicenses */
            $whitelistedLicenses = $config['whitelisted_licenses'];

            /** @var array<int, string> $restrictiveLicenses */
            $restrictiveLicenses = $config['restrictive_licenses'];

            // Check if any license is whitelisted
            $hasWhitelistedLicense = ! empty(array_intersect(
                $normalizedLicenses,
                array_map('strtoupper', $whitelistedLicenses)
            ));

            // Check for restrictive licenses
            $restrictiveMatches = array_intersect(
                $normalizedLicenses,
                array_map('strtoupper', $restrictiveLicenses)
            );

            // If package has whitelisted license, it's OK (dual-license scenario)
            if ($hasWhitelistedLicense) {
                continue;
            }

            // Check for restrictive licenses (only if no whitelisted license exists)
            if (! empty($restrictiveMatches)) {
                $severity = $isDevDependency ? Severity::Low : Severity::Critical;
                $prefix = $isDevDependency ? 'Dev package' : 'Package';

                $issues[] = $this->createIssue(
                    message: sprintf(
                        '%s "%s" uses restrictive license: %s',
                        $prefix,
                        $packageName,
                        implode(', ', $licenses)
                    ),
                    location: new Location($composerLock),
                    severity: $severity,
                    recommendation: $isDevDependency
                        ? sprintf('Dev dependency "%s" has GPL/AGPL license. This is generally safe for development tools, but verify it\'s not distributed with your application', $packageName)
                        : sprintf('GPL/AGPL licenses may require your application to be open-source. Review "%s" license implications or find an alternative package', $packageName),
                    code: FileParser::getCodeSnippet($composerLock, 1),
                    metadata: [
                        'package' => $packageName,
                        'licenses' => $licenses,
                        'issue_type' => 'restrictive_license',
                        'type' => $isDevDependency ? 'dev_dependency' : 'production_dependency',
                    ]
                );
            } else {
                // License is not whitelisted and not explicitly restrictive - flag for review (production only)
                if (! $isDevDependency) {
                    $issues[] = $this->createIssue(
                        message: sprintf(
                            'Package "%s" uses non-standard license: %s',
                            $packageName,
                            implode(', ', $licenses)
                        ),
                        location: new Location($composerLock),
                        severity: Severity::Low,
                        recommendation: sprintf(
                            'Review the "%s" license terms to ensure compatibility with your application. Common safe licenses: MIT, Apache-2.0, BSD',
                            $packageName
                        ),
                        code: FileParser::getCodeSnippet($composerLock, 1),
                        metadata: [
                            'package' => $packageName,
                            'licenses' => $licenses,
                            'issue_type' => 'unknown_license',
                        ]
                    );
                }
            }
        }
    }

    /**
     * Normalize license field to array (handle both string and array).
     *
     * @param  array<string, mixed>  $package
     * @return array<int, string>
     */
    private function normalizeLicenseField(array $package): array
    {
        if (! isset($package['license'])) {
            return [];
        }

        $license = $package['license'];

        // Handle string license
        if (is_string($license)) {
            return [$license];
        }

        // Handle array license
        if (is_array($license)) {
            return $license;
        }

        return [];
    }

    /**
     * Get analyzer configuration.
     *
     * @return array<string, mixed>
     */
    private function getConfiguration(): array
    {
        /** @var array<string, mixed> $config */
        $config = config('shieldci.license_compliance', []);

        return array_merge([
            'whitelisted_licenses' => $this->whitelistedLicenses,
            'restrictive_licenses' => $this->restrictiveLicenses,
        ], $config);
    }
}
