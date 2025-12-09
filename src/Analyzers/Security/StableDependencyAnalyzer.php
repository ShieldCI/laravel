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
use Throwable;

/**
 * Validates that dependencies use stable versions rather than dev/beta/alpha.
 *
 * Checks for:
 * - Dev versions (dev-master, dev-main)
 * - Alpha/Beta/RC versions
 * - Unstable version constraints
 * - Missing prefer-stable configuration
 */
class StableDependencyAnalyzer extends AbstractFileAnalyzer
{
    private const PREFER_STABLE_CHANGE_PATTERNS = ['Upgrading', 'Downgrading'];

    public function __construct(
        private Composer $composer
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'stable-dependencies',
            name: 'Stable Dependencies Analyzer',
            description: 'Validates that all dependencies use stable versions rather than dev/alpha/beta releases',
            category: Category::Security,
            severity: Severity::Low,
            tags: ['dependencies', 'composer', 'stability', 'versions', 'production'],
            docsUrl: 'https://docs.shieldci.com/analyzers/security/stable-dependencies',
            timeToFix: 30
        );
    }

    public function shouldRun(): bool
    {
        // Only run if composer.json exists
        $composerJson = $this->buildPath('composer.json');

        return file_exists($composerJson);
    }

    public function getSkipReason(): string
    {
        return 'No composer.json found';
    }

    protected function runAnalysis(): ResultInterface
    {
        $issues = [];

        // Get composer.json path (we know it exists from shouldRun())
        $composerJson = $this->buildPath('composer.json');

        $this->checkComposerConfiguration($composerJson, $issues);

        // Check composer.lock for unstable versions
        $composerLock = $this->buildPath('composer.lock');
        if (file_exists($composerLock)) {
            $this->checkComposerLock($composerLock, $issues);
        }

        try {
            $preferStableOutput = $this->composer->updateDryRun(['--prefer-stable']);
            if ($this->preferStableRunChangesDependencies($preferStableOutput)) {
                $filePath = file_exists($composerLock) ? $composerLock : $composerJson;
                $issues[] = $this->createIssue(
                    message: 'Composer update --prefer-stable would modify installed packages',
                    location: new Location(
                        $this->getRelativePath($filePath),
                        1
                    ),
                    severity: Severity::Low,
                    recommendation: 'Run "composer update --prefer-stable" and ensure all dependencies resolve to stable releases.',
                    code: FileParser::getCodeSnippet($filePath, 1),
                    metadata: [
                        'composer_version_check' => 'update --dry-run --prefer-stable',
                    ]
                );
            }
        } catch (Throwable $exception) {
            return $this->error(
                sprintf('Unable to verify dependency stability: %s', $exception->getMessage())
            );
        }

        if (empty($issues)) {
            return $this->passed('All dependencies are using stable versions');
        }

        return $this->failed(
            sprintf('Found %d dependency stability issue(s)', count($issues)),
            $issues
        );
    }

    /**
     * Parse JSON file and return array or empty array on error.
     *
     * @return array<string, mixed>
     */
    private function parseJsonFile(string $path): array
    {
        if (! file_exists($path)) {
            return [];
        }

        $content = FileParser::readFile($path);
        if ($content === null) {
            return [];
        }

        $decoded = json_decode($content, true);
        if (json_last_error() !== JSON_ERROR_NONE || ! is_array($decoded)) {
            return [];
        }

        return $decoded;
    }

    /**
     * Check composer.json configuration.
     */
    private function checkComposerConfiguration(string $composerJson, array &$issues): void
    {
        $data = $this->parseJsonFile($composerJson);
        if (empty($data)) {
            return;
        }

        // Check minimum-stability setting
        $minimumStability = isset($data['minimum-stability']) && is_string($data['minimum-stability'])
            ? $data['minimum-stability']
            : 'stable';

        if ($minimumStability !== 'stable') {
            $line = $this->findMinimumStabilityLine($composerJson);
            $issues[] = $this->createIssue(
                message: sprintf('Composer minimum-stability is set to "%s" instead of "stable"', $minimumStability),
                location: new Location(
                    $this->getRelativePath($composerJson),
                    $line
                ),
                severity: Severity::Medium,
                recommendation: 'Set "minimum-stability": "stable" in composer.json to prefer stable package versions',
                code: FileParser::getCodeSnippet($composerJson, $line),
                metadata: ['minimum_stability' => $minimumStability]
            );
        }

        // Check if prefer-stable is enabled
        if (! isset($data['prefer-stable']) || $data['prefer-stable'] !== true) {
            $line = $this->findPreferStableLine($composerJson);
            $issues[] = $this->createIssue(
                message: 'Composer prefer-stable is not enabled',
                location: new Location(
                    $this->getRelativePath($composerJson),
                    $line
                ),
                severity: Severity::Low,
                recommendation: 'Set "prefer-stable": true in composer.json to prefer stable versions when possible',
                code: FileParser::getCodeSnippet($composerJson, $line),
                metadata: []
            );
        }

        // Check for dev version constraints in require section
        if (isset($data['require']) && is_array($data['require'])) {
            $this->checkVersionConstraints($data['require'], 'require', $issues, $composerJson);
        }

        // Check for dev version constraints in require-dev section
        // These can leak into production if minimum-stability is not "stable"
        if (isset($data['require-dev']) && is_array($data['require-dev'])) {
            $this->checkVersionConstraints($data['require-dev'], 'require-dev', $issues, $composerJson);
        }
    }

    /**
     * Check if version string indicates an unstable release.
     */
    private function isUnstableVersion(string $version): bool
    {
        $lowerVersion = strtolower($version);

        // Check for dev versions: dev-master, dev-main, 2.0.x-dev, etc.
        if (str_contains($lowerVersion, 'dev-') || str_ends_with($lowerVersion, '-dev')) {
            return true;
        }

        // Check for alpha/beta/RC with various formats
        // Matches: 1.0.0-alpha, v1.0.0-beta1, 2.0.0-RC1, etc.
        if (preg_match('/-(alpha|beta|rc)([.\d-]*)$/i', $lowerVersion)) {
            return true;
        }

        return false;
    }

    /**
     * Extract stability flag from version string.
     * Returns null if no stability flag found.
     */
    private function extractStabilityFlag(string $version): ?string
    {
        if (preg_match('/@(dev|alpha|beta|rc)/i', $version, $matches)) {
            return $matches[1];
        }

        return null;
    }

    /**
     * Check version constraints for unstable patterns.
     */
    private function checkVersionConstraints(array $packages, string $section, array &$issues, string $composerJson): void
    {
        foreach ($packages as $package => $version) {
            if (! is_string($package) || ! is_string($version)) {
                continue;
            }

            // Skip PHP and extensions
            if ($package === 'php' || str_starts_with($package, 'ext-')) {
                continue;
            }

            $line = $this->findPackageLine($composerJson, $package, $section);

            // Check for dev versions (dev-master, dev-main, 2.0.x-dev)
            if ($this->isUnstableVersion($version)) {
                $issues[] = $this->createIssue(
                    message: sprintf('Package "%s" in %s requires unstable dev version: %s', $package, $section, $version),
                    location: new Location(
                        $this->getRelativePath($composerJson),
                        $line
                    ),
                    severity: Severity::Medium,
                    recommendation: sprintf('Update "%s" to use a stable version constraint', $package),
                    code: FileParser::getCodeSnippet($composerJson, $line),
                    metadata: ['package' => $package, 'version' => $version, 'section' => $section]
                );

                // Skip stability flag check to avoid double-counting
                continue;
            }

            // Check for @dev, @alpha, @beta, @RC stability flags (only if not already flagged above)
            $stabilityFlag = $this->extractStabilityFlag($version);
            if ($stabilityFlag !== null) {
                $issues[] = $this->createIssue(
                    message: sprintf('Package "%s" in %s requires unstable version: %s', $package, $section, $version),
                    location: new Location(
                        $this->getRelativePath($composerJson),
                        $line
                    ),
                    severity: Severity::Medium,
                    recommendation: sprintf('Remove @%s flag and use stable version for "%s"', $stabilityFlag, $package),
                    code: FileParser::getCodeSnippet($composerJson, $line),
                    metadata: ['package' => $package, 'version' => $version, 'stability' => $stabilityFlag, 'section' => $section]
                );
            }
        }
    }

    /**
     * Check composer.lock for unstable installed versions.
     */
    private function checkComposerLock(string $composerLock, array &$issues): void
    {
        $lockData = $this->parseJsonFile($composerLock);
        if (empty($lockData)) {
            return;
        }

        $packages = array_merge(
            isset($lockData['packages']) && is_array($lockData['packages']) ? $lockData['packages'] : [],
            isset($lockData['packages-dev']) && is_array($lockData['packages-dev']) ? $lockData['packages-dev'] : []
        );

        if (empty($packages)) {
            return;
        }

        $unstablePackages = [];

        foreach ($packages as $package) {
            if (! is_array($package)) {
                continue;
            }

            $packageName = isset($package['name']) && is_string($package['name'])
                ? $package['name']
                : 'Unknown';

            $version = isset($package['version']) && is_string($package['version'])
                ? $package['version']
                : '';

            // Check for unstable versions using the same logic as checkVersionConstraints
            if ($this->isUnstableVersion($version)) {
                $unstablePackages[] = sprintf('%s (%s)', $packageName, $version);
            }
        }

        if (! empty($unstablePackages)) {
            $count = count($unstablePackages);
            $examples = implode(', ', array_slice($unstablePackages, 0, 3));

            $issues[] = $this->createIssue(
                message: sprintf('Found %d unstable package versions installed', $count),
                location: new Location(
                    $this->getRelativePath($composerLock),
                    1
                ),
                severity: Severity::Low,
                recommendation: sprintf(
                    'Update to stable versions: %s%s. Run "composer update --prefer-stable"',
                    $examples,
                    $count > 3 ? sprintf(' and %d more', $count - 3) : ''
                ),
                code: FileParser::getCodeSnippet($composerLock, 1),
                metadata: [
                    'count' => $count,
                    'examples' => array_slice($unstablePackages, 0, 3),
                ]
            );
        }
    }

    private function preferStableRunChangesDependencies(string $output): bool
    {
        foreach (self::PREFER_STABLE_CHANGE_PATTERNS as $pattern) {
            if (str_contains($output, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Find the line number where a package is defined in composer.json.
     */
    private function findPackageLine(string $composerJson, string $package, string $section = 'require'): int
    {
        if (! file_exists($composerJson)) {
            return 1;
        }

        $lines = FileParser::getLines($composerJson);
        if (empty($lines)) {
            return 1;
        }

        $inSection = false;
        $pattern = '/^\s*"'.preg_quote($package, '/').'"\s*:/';

        foreach ($lines as $index => $line) {
            if (! is_string($line)) {
                continue;
            }

            // Check if we're entering the target section
            if (preg_match('/^\s*"'.$section.'"\s*:/', $line) === 1) {
                $inSection = true;

                continue;
            }

            // Check if we're leaving the section (closing brace)
            if ($inSection && preg_match('/^\s*}/', $line) === 1) {
                $inSection = false;
            }

            // If in section, look for package name
            if ($inSection && preg_match($pattern, $line) === 1) {
                return $index + 1;
            }
        }

        return 1;
    }

    /**
     * Find the line number of minimum-stability setting.
     */
    private function findMinimumStabilityLine(string $composerJson): int
    {
        if (! file_exists($composerJson)) {
            return 1;
        }

        $lines = FileParser::getLines($composerJson);
        if (empty($lines)) {
            return 1;
        }

        foreach ($lines as $index => $line) {
            if (! is_string($line)) {
                continue;
            }

            if (preg_match('/^\s*"minimum-stability"\s*:/', $line) === 1) {
                return $index + 1;
            }
        }

        return 1;
    }

    /**
     * Find the line number of prefer-stable setting.
     * Falls back to line 1 if not found (since the setting is missing).
     */
    private function findPreferStableLine(string $composerJson): int
    {
        if (! file_exists($composerJson)) {
            return 1;
        }

        $lines = FileParser::getLines($composerJson);
        if (empty($lines)) {
            return 1;
        }

        foreach ($lines as $index => $line) {
            if (! is_string($line)) {
                continue;
            }

            if (preg_match('/^\s*"prefer-stable"\s*:/', $line) === 1) {
                return $index + 1;
            }
        }

        // If not found, return line 1 (setting is missing)
        return 1;
    }
}
