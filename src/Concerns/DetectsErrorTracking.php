<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use Illuminate\Support\Env;
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
     * Composer package names are case-insensitive, so both sides are compared lowercased.
     *
     * @param  array<string>  $packages
     * @param  array<string, true>  $installed  lowercased names, from productionPackages()
     */
    protected function hasProductionErrorTracker(array $packages, array $installed): bool
    {
        foreach ($packages as $package) {
            $name = strtolower($package);

            if (isset($installed[$name]) && ! $this->isSwitchedOff($name)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Names of the packages a --no-dev deploy installs, and the manifest they came from.
     *
     * Exact names from composer.lock's "packages" section; "packages-dev" is left out, and
     * matching names rather than searching the raw file ignores a package that is only named
     * in another package's requirements. Without a lock file, the keys of composer.json's
     * "require". Names are lowercased, as Composer compares them.
     *
     * A manifest that cannot be read or decoded sets `problem` and leaves `packages` empty,
     * so a broken manifest is inconclusive rather than "nothing installed".
     *
     * @return array{manifest: string, packages: array<string, true>, problem: string|null}
     */
    protected function productionPackages(): array
    {
        $manifest = file_exists($this->buildPath('composer.lock')) ? 'composer.lock' : 'composer.json';
        $broken = fn (string $problem): array => ['manifest' => $manifest, 'packages' => [], 'problem' => $problem];

        $content = FileParser::readFile($this->buildPath($manifest));
        if ($content === null) {
            return $broken('could not be read');
        }

        $decoded = json_decode($content, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            return $broken('contains invalid JSON and cannot be parsed');
        }

        if (! is_array($decoded)) {
            return $broken('does not contain a JSON object');
        }

        if ($manifest === 'composer.json') {
            $require = is_array($decoded['require'] ?? null) ? $decoded['require'] : [];
            $names = array_map(fn (int|string $name): string => strtolower((string) $name), array_keys($require));

            return ['manifest' => $manifest, 'packages' => array_fill_keys($names, true), 'problem' => null];
        }

        if (! is_array($decoded['packages'] ?? null)) {
            return $broken('has no "packages" list');
        }

        $names = [];
        foreach ($decoded['packages'] as $package) {
            if (is_array($package) && is_string($package['name'] ?? null)) {
                $names[strtolower($package['name'])] = true;
            }
        }

        return ['manifest' => $manifest, 'packages' => $names, 'problem' => null];
    }

    /**
     * Whether an installed tracker is configured not to report.
     */
    private function isSwitchedOff(string $package): bool
    {
        return match ($package) {
            'laravel/nightwatch' => $this->isNightwatchSwitchedOff(),
            default => false,
        };
    }

    /**
     * Whether Nightwatch's 'enabled' resolves to false or its 'token' to an empty value.
     *
     * A key config/nightwatch.php does not publish keeps the package's stock value,
     * env('NIGHTWATCH_ENABLED', true) and env('NIGHTWATCH_TOKEN'), and an env() call in the
     * published file is taken to read that same variable.
     *
     * Only explicit values count. A literal is read from the config file; an env() value only
     * when the running application's environment or .env assigns it. Another project's server
     * variables are not in this process, so for any other base path only .env is read, and a
     * variable it leaves out may still come from the server, as Laravel Cloud and Vapor provide them.
     */
    private function isNightwatchSwitchedOff(): bool
    {
        $config = $this->nightwatchConfig();

        $enabled = $config['enabled'] ?? null;
        if ($enabled !== null && ! $enabled['isEnvCall']) {
            if ($enabled['value'] === false) {
                return true;
            }
        } elseif (in_array(strtolower((string) $this->envValue('NIGHTWATCH_ENABLED')), ['false', '(false)'], true)) {
            return true;
        }

        $token = $config['token'] ?? null;
        if ($token !== null && ! $token['isEnvCall']) {
            return $token['value'] === '';
        }

        $envToken = $this->envValue('NIGHTWATCH_TOKEN');

        // env() reads these as null or an empty string
        return $envToken !== null && in_array(strtolower($envToken), ['', 'null', '(null)', 'empty', '(empty)'], true);
    }

    /**
     * Top-level entries of config/nightwatch.php, or none when it is not published.
     *
     * Goes through the shared parser, never a private instance, so a file that does not parse
     * lands on the failure log the report reads (see InspectsCode, which this trait cannot
     * use: its private $parser clashes with the one analyzers inject).
     *
     * @return array<string, array{value: mixed, line: int, isEnvCall: bool, envDefault: mixed, envHasDefault: bool}>
     */
    private function nightwatchConfig(): array
    {
        $configPath = $this->buildPath('config', 'nightwatch.php');
        if (! file_exists($configPath)) {
            return [];
        }

        return (new ConfigFileParser(app(AstParser::class)))->parseArray($configPath);
    }

    /**
     * The value env() would read $key from, unconverted, or null when nothing assigns it.
     *
     * For the running application that is its environment repository first, where platform
     * variables override .env as they do at runtime, then .env, which a cached config leaves
     * unloaded. The repository is read raw because env() turns "(false)" into false and both
     * "null" and an unset variable into null, so a token set to null would read as unset.
     */
    private function envValue(string $key): ?string
    {
        $value = $this->analyzesRunningApp() ? Env::getRepository()->get($key) : null;

        return $value ?? $this->envFileValue($key);
    }

    /**
     * Whether the analyzed base path is the application running this analysis, compared
     * resolved, since deploy and temporary directories are often reached through symlinks.
     */
    private function analyzesRunningApp(): bool
    {
        $running = realpath(base_path());

        return $running !== false && $running === realpath($this->getBasePath());
    }

    /**
     * The value .env assigns to $key, unquoted and without a trailing comment, or null when
     * .env does not assign it.
     */
    private function envFileValue(string $key): ?string
    {
        foreach (FileParser::getLines($this->buildPath('.env')) as $line) {
            if (preg_match('/^\s*(?:export\s+)?'.preg_quote($key, '/').'\s*=(.*)$/', $line, $matches) !== 1) {
                continue;
            }

            $value = trim($matches[1]);

            if (preg_match('/^(["\'])(.*?)\1/', $value, $quoted) === 1) {
                return $quoted[2];
            }

            return trim((string) preg_replace('/(^|\s)#.*$/', '', $value));
        }

        return null;
    }
}
