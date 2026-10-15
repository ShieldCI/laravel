<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\AnalyzersCore\Support\ConfigFileParser;
use ShieldCI\AnalyzersCore\Support\FileParser;

/**
 * Answers "will an error tracker report in production?" from the project's Composer files.
 *
 * Owns the canonical list of error-tracking packages so that analyzers asking the same
 * question share one inventory instead of keeping copies that drift apart.
 */
trait DetectsErrorTracking
{
    /**
     * Dedicated production error-tracking SDKs, each of which reports unhandled exceptions
     * once installed and configured.
     *
     * Excludes facade/ignition, spatie/laravel-ignition, spatie/laravel-ray and
     * spatie/flare-client-php: development tools, normally installed as dev dependencies.
     * spatie/laravel-flare is the production Flare client and is included.
     * Excludes aws/aws-sdk-php: too broad, used for S3, SES and SQS without error tracking.
     *
     * @return list<string>
     */
    protected function errorTrackingPackages(): array
    {
        return [
            'sentry/sentry-laravel',
            'bugsnag/bugsnag-laravel',
            'rollbar/rollbar-laravel',
            'airbrake/phpbrake',
            'honeybadger-io/honeybadger-laravel',
            'spatie/laravel-flare',
            'inspector-apm/inspector-laravel',
            'laravel/nightwatch',
        ];
    }

    /**
     * Whether any of the given packages is installed for production and not switched off.
     *
     * @param  array<string>  $packages
     * @param  array<string, true>  $installed  from productionPackageNames()
     */
    protected function hasProductionErrorTracker(array $packages, array $installed): bool
    {
        foreach ($packages as $package) {
            if (! isset($installed[$package])) {
                continue;
            }

            if ($package === 'laravel/nightwatch' && $this->isNightwatchDisabledInConfig()) {
                continue;
            }

            return true;
        }

        return false;
    }

    /**
     * The file productionPackageNames() reads: composer.lock, or composer.json without one.
     */
    protected function productionManifest(): string
    {
        return file_exists($this->buildPath('composer.lock')) ? 'composer.lock' : 'composer.json';
    }

    /**
     * Names of the packages a --no-dev deploy installs.
     *
     * Exact names from composer.lock's "packages" section; "packages-dev" is left out, and
     * matching names rather than searching the raw file ignores a package that is only named
     * in another package's requirements. Without a lock file, the keys of composer.json's
     * "require". Null when that file cannot be read or decoded, so a broken manifest is
     * inconclusive rather than "nothing installed".
     *
     * @return array<string, true>|null
     */
    protected function productionPackageNames(): ?array
    {
        $manifest = $this->productionManifest();
        $content = FileParser::readFile($this->buildPath($manifest));
        $decoded = $content === null ? null : json_decode($content, true);

        if ($manifest === 'composer.json') {
            if (! is_array($decoded)) {
                return null;
            }

            $require = is_array($decoded['require'] ?? null) ? $decoded['require'] : [];

            return array_fill_keys(array_map('strval', array_keys($require)), true);
        }

        if (! is_array($decoded) || ! is_array($decoded['packages'] ?? null)) {
            return null;
        }

        $names = [];
        foreach ($decoded['packages'] as $package) {
            if (is_array($package) && is_string($package['name'] ?? null)) {
                $names[$package['name']] = true;
            }
        }

        return $names;
    }

    /**
     * Whether config/nightwatch.php hard-codes 'enabled' => false.
     *
     * Only a literal false counts. An env() call, even one defaulting to false, is decided per
     * environment, and a missing or unparseable file is no evidence either way. The shared
     * parser records a file that does not parse, so the report still names it.
     */
    private function isNightwatchDisabledInConfig(): bool
    {
        $configPath = $this->buildPath('config', 'nightwatch.php');
        if (! file_exists($configPath)) {
            return false;
        }

        // ConfigFileParser reports an env() call with a null value, whatever its default
        $enabled = (new ConfigFileParser(app(AstParser::class)))->parseArray($configPath)['enabled'] ?? null;

        return $enabled !== null && $enabled['value'] === false;
    }
}
