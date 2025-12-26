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
use ShieldCI\Support\Composer;

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

            // Find the line number where this package is defined
            $lineNumber = Composer::findPackageLineNumber($composerLock, $packageName);

            // Normalize license to array and detect if it's conjunctive (AND) or disjunctive (OR)
            $licenseData = $this->parseLicenseField($package);
            $licenses = $licenseData['licenses'];
            $isConjunctive = $licenseData['is_conjunctive'];

            // Skip if no license information
            if (empty($licenses)) {
                // Only flag missing licenses for production dependencies
                if (! $isDevDependency) {
                    $issues[] = $this->createIssue(
                        message: sprintf('Package "%s" has no license information', $packageName),
                        location: new Location($composerLock, $lineNumber),
                        severity: Severity::Medium,
                        recommendation: sprintf('Investigate license for "%s" or contact the package maintainer', $packageName),
                        code: FileParser::getCodeSnippet($composerLock, $lineNumber),
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

            // Check which licenses are whitelisted
            $whitelistedMatches = array_intersect(
                $normalizedLicenses,
                array_map('strtoupper', $whitelistedLicenses)
            );

            // Check for restrictive licenses
            $restrictiveMatches = array_intersect(
                $normalizedLicenses,
                array_map('strtoupper', $restrictiveLicenses)
            );

            // Determine if package is acceptable based on license type:
            // - Disjunctive (OR): If ANY license is whitelisted, package is OK
            // - Conjunctive (AND): ALL licenses must be whitelisted, otherwise problematic
            $isAcceptable = false;
            if ($isConjunctive) {
                // For AND licenses, ALL must be whitelisted (no restrictive licenses allowed)
                $isAcceptable = count($whitelistedMatches) === count($licenses) && empty($restrictiveMatches);
            } else {
                // For OR licenses, ANY whitelisted license makes it acceptable
                $isAcceptable = ! empty($whitelistedMatches);
            }

            // If package is acceptable, skip it
            if ($isAcceptable) {
                continue;
            }

            // Check for restrictive licenses
            if (! empty($restrictiveMatches)) {
                $severity = $isDevDependency ? Severity::Low : Severity::Critical;
                $prefix = $isDevDependency ? 'Dev package' : 'Package';

                $licenseType = $isConjunctive ? ' (conjunctive - ALL apply)' : ' (disjunctive - choose one)';

                $issues[] = $this->createIssue(
                    message: sprintf(
                        '%s "%s" uses restrictive license: %s%s',
                        $prefix,
                        $packageName,
                        implode(', ', $licenses),
                        $licenseType
                    ),
                    location: new Location($composerLock, $lineNumber),
                    severity: $severity,
                    recommendation: $isDevDependency
                        ? sprintf('Dev dependency "%s" has GPL/AGPL license. This is generally safe for development tools, but verify it\'s not distributed with your application', $packageName)
                        : ($isConjunctive
                            ? sprintf('Package "%s" has conjunctive license (AND) including GPL/AGPL - ALL licenses apply simultaneously. You must comply with GPL/AGPL terms. Consider finding an alternative package', $packageName)
                            : sprintf('GPL/AGPL licenses may require your application to be open-source. Review "%s" license implications or find an alternative package', $packageName)),
                    code: FileParser::getCodeSnippet($composerLock, $lineNumber),
                    metadata: [
                        'package' => $packageName,
                        'licenses' => $licenses,
                        'license_type' => $isConjunctive ? 'conjunctive' : 'disjunctive',
                        'issue_type' => 'restrictive_license',
                        'type' => $isDevDependency ? 'dev_dependency' : 'production_dependency',
                    ]
                );
            } else {
                // License is not whitelisted and not explicitly restrictive - flag for review (production only)
                if (! $isDevDependency) {
                    $licenseType = $isConjunctive ? ' (conjunctive - ALL apply)' : ' (disjunctive - choose one)';

                    $issues[] = $this->createIssue(
                        message: sprintf(
                            'Package "%s" uses non-standard license: %s%s',
                            $packageName,
                            implode(', ', $licenses),
                            $licenseType
                        ),
                        location: new Location($composerLock, $lineNumber),
                        severity: Severity::Low,
                        recommendation: sprintf(
                            'Review the "%s" license terms to ensure compatibility with your application. %s Common safe licenses: MIT, Apache-2.0, BSD',
                            $packageName,
                            $isConjunctive ? 'Note: This is a conjunctive license (AND) - ALL licenses apply simultaneously.' : ''
                        ),
                        code: FileParser::getCodeSnippet($composerLock, $lineNumber),
                        metadata: [
                            'package' => $packageName,
                            'licenses' => $licenses,
                            'license_type' => $isConjunctive ? 'conjunctive' : 'disjunctive',
                            'issue_type' => 'unknown_license',
                        ]
                    );
                }
            }
        }
    }

    /**
     * Parse license field and detect if it's conjunctive (AND) or disjunctive (OR).
     *
     * Composer/SPDX supports three license formats:
     * 1. String: "MIT" (single license)
     * 2. Array: ["MIT", "GPL-3.0"] (disjunctive - OR - choose one)
     * 3. SPDX expression: "(MIT and GPL-3.0)" or "MIT or GPL-3.0" (conjunctive or disjunctive)
     *
     * @param  array<string, mixed>  $package
     * @return array{licenses: array<int, string>, is_conjunctive: bool}
     */
    private function parseLicenseField(array $package): array
    {
        if (! isset($package['license'])) {
            return ['licenses' => [], 'is_conjunctive' => false];
        }

        $license = $package['license'];

        // Handle array license (composer format - always disjunctive/OR)
        if (is_array($license)) {
            return [
                'licenses' => $license,
                'is_conjunctive' => false,  // Arrays in composer.json are always OR
            ];
        }

        // Handle string license
        if (is_string($license)) {
            // Check for SPDX expressions with operators
            $lowercaseLicense = strtolower($license);

            // Detect conjunctive (AND) licenses
            // Patterns: "MIT and GPL-3.0", "(MIT and GPL-3.0)", "MIT AND GPL-3.0"
            if (preg_match('/\band\b/i', $license)) {
                // Extract individual licenses from the expression
                // Remove parentheses and split by 'and'
                $cleanedLicense = preg_replace('/[()]/', '', $license);
                if ($cleanedLicense === null) {
                    return ['licenses' => [$license], 'is_conjunctive' => false];
                }

                $parts = preg_split('/\s+and\s+/i', $cleanedLicense);
                if ($parts === false) {
                    return ['licenses' => [$license], 'is_conjunctive' => false];
                }

                $licenses = array_map('trim', $parts);

                return [
                    'licenses' => $licenses,
                    'is_conjunctive' => true,
                ];
            }

            // Detect disjunctive (OR) licenses in string format
            // Patterns: "MIT or GPL-3.0", "(MIT or GPL-3.0)", "MIT OR GPL-3.0"
            if (preg_match('/\bor\b/i', $license)) {
                // Extract individual licenses from the expression
                $cleanedLicense = preg_replace('/[()]/', '', $license);
                if ($cleanedLicense === null) {
                    return ['licenses' => [$license], 'is_conjunctive' => false];
                }

                $parts = preg_split('/\s+or\s+/i', $cleanedLicense);
                if ($parts === false) {
                    return ['licenses' => [$license], 'is_conjunctive' => false];
                }

                $licenses = array_map('trim', $parts);

                return [
                    'licenses' => $licenses,
                    'is_conjunctive' => false,
                ];
            }

            // Single license (no operators)
            return [
                'licenses' => [$license],
                'is_conjunctive' => false,
            ];
        }

        return ['licenses' => [], 'is_conjunctive' => false];
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
