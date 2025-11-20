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
            name: 'Dependency License Analyzer',
            description: 'Validates that all dependencies use legally acceptable licenses for your application type',
            category: Category::Security,
            severity: Severity::Critical,
            tags: ['licenses', 'legal', 'compliance', 'dependencies', 'gpl', 'commercial'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/license-compliance'
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Check composer.lock for PHP dependencies
        $composerLock = $this->basePath.'/composer.lock';

        if (! file_exists($composerLock)) {
            return $this->passed('No composer.lock found - skipping license check');
        }

        $this->checkComposerLicenses($composerLock, $issues);

        if (empty($issues)) {
            return $this->passed('All dependency licenses are acceptable');
        }

        return $this->failed(
            sprintf('Found %d packages with potentially problematic licenses', count($issues)),
            $issues
        );
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

        if (! isset($lockData['packages'])) {
            return;
        }

        foreach ($lockData['packages'] as $package) {
            $packageName = $package['name'] ?? 'Unknown';
            $licenses = $package['license'] ?? [];

            // Skip if no license information
            if (empty($licenses)) {
                $issues[] = $this->createIssue(
                    message: sprintf('Package "%s" has no license information', $packageName),
                    location: new Location(
                        'composer.lock',
                        1
                    ),
                    severity: Severity::Medium,
                    recommendation: sprintf('Investigate license for "%s" or contact the package maintainer', $packageName),
                    code: sprintf('No license: %s', $packageName)
                );

                continue;
            }

            // Normalize licenses to uppercase for comparison
            $normalizedLicenses = array_map('strtoupper', $licenses);

            // Check if any license is whitelisted
            $hasWhitelistedLicense = ! empty(array_intersect(
                $normalizedLicenses,
                array_map('strtoupper', $this->whitelistedLicenses)
            ));

            // Check for restrictive licenses
            $restrictiveMatches = array_intersect(
                $normalizedLicenses,
                array_map('strtoupper', $this->restrictiveLicenses)
            );

            if (! empty($restrictiveMatches)) {
                $issues[] = $this->createIssue(
                    message: sprintf(
                        'Package "%s" uses restrictive license: %s',
                        $packageName,
                        implode(', ', $licenses)
                    ),
                    location: new Location(
                        'composer.lock',
                        1
                    ),
                    severity: Severity::Critical,
                    recommendation: sprintf(
                        'GPL/AGPL licenses may require your application to be open-source. Review "%s" license implications or find an alternative package',
                        $packageName
                    ),
                    code: sprintf('Restrictive license: %s [%s]', $packageName, implode(', ', $licenses))
                );
            } elseif (! $hasWhitelistedLicense) {
                // License is not whitelisted and not explicitly restrictive - flag for review
                $issues[] = $this->createIssue(
                    message: sprintf(
                        'Package "%s" uses non-standard license: %s',
                        $packageName,
                        implode(', ', $licenses)
                    ),
                    location: new Location(
                        'composer.lock',
                        1
                    ),
                    severity: Severity::Medium,
                    recommendation: sprintf(
                        'Review the "%s" license terms to ensure compatibility with your application. Common safe licenses: MIT, Apache-2.0, BSD',
                        implode(', ', $licenses)
                    ),
                    code: sprintf('Non-standard license: %s [%s]', $packageName, implode(', ', $licenses))
                );
            }
        }

        // Check dev dependencies separately (less critical)
        if (isset($lockData['packages-dev'])) {
            foreach ($lockData['packages-dev'] as $package) {
                $packageName = $package['name'] ?? 'Unknown';
                $licenses = $package['license'] ?? [];

                if (empty($licenses)) {
                    continue; // Skip missing licenses for dev dependencies
                }

                $normalizedLicenses = array_map('strtoupper', $licenses);

                // Only flag GPL/AGPL in dev dependencies as warning (not critical)
                $restrictiveMatches = array_intersect(
                    $normalizedLicenses,
                    array_map('strtoupper', $this->restrictiveLicenses)
                );

                if (! empty($restrictiveMatches)) {
                    $issues[] = $this->createIssue(
                        message: sprintf(
                            'Dev package "%s" uses restrictive license: %s',
                            $packageName,
                            implode(', ', $licenses)
                        ),
                        location: new Location(
                            'composer.lock',
                            1
                        ),
                        severity: Severity::Low,
                        recommendation: sprintf(
                            'Dev dependency "%s" has GPL/AGPL license. This is generally safe for development tools, but verify it\'s not distributed with your application',
                            $packageName
                        ),
                        code: sprintf('Dev dependency: %s [%s]', $packageName, implode(', ', $licenses))
                    );
                }
            }
        }
    }
}
