<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Routing\Router;
use ShieldCI\AnalyzersCore\Abstracts\AbstractAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\ConfigFileHelper;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Concerns\AnalyzesMiddleware;

/**
 * Analyzes session driver configuration for performance and scalability.
 *
 * Checks for:
 * - Null session driver (sessions disabled while routes use them)
 * - File session driver in multi-server environments
 * - Cookie session driver limitations
 * - Array session driver in production
 * - Recommends Redis/Database for production
 *
 * This analyzer uses Laravel's config repository and checks if sessions
 * are actually used before warning about driver choice.
 */
class SessionDriverAnalyzer extends AbstractAnalyzer
{
    use AnalyzesMiddleware;

    public static bool $runInCI = false;

    /**
     * Allows tests to override stateless detection.
     */
    protected ?bool $statelessOverride = null;

    public function __construct(
        private Config $config,
        Router $router,
        Kernel $kernel
    ) {
        $this->configRepository = $config;
        $this->router = $router;
        $this->kernel = $kernel;
    }

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'session-driver',
            name: 'Session Driver Configuration Analyzer',
            description: 'Ensures a proper session driver is configured for scalability and performance',
            category: Category::Performance,
            severity: Severity::Critical,
            tags: ['session', 'performance', 'configuration', 'redis', 'scalability'],
            timeToFix: 30
        );
    }

    public function shouldRun(): bool
    {
        try {
            if ($this->statelessOverride !== null) {
                return ! $this->statelessOverride;
            }

            return ! $this->appIsStateless();
        } catch (\ReflectionException $e) {
            return true;
        }
    }

    public function getSkipReason(): string
    {
        return 'Not applicable for stateless/API-only applications (no session middleware detected)';
    }

    public function setStatelessOverride(?bool $stateless): void
    {
        $this->statelessOverride = $stateless;
    }

    protected function runAnalysis(): ResultInterface
    {
        $driver = $this->config->get('session.driver', 'file');
        $environment = $this->getEnvironment();

        // A malformed driver is a fact about the user's configuration, not a failure of
        // this analyzer, so it is reported as a located finding like every other driver
        // verdict below. As an errored result it carried no issue, which left it
        // unbaselineable and unsuppressible.
        if (! is_string($driver)) {
            return $this->failed(
                'Session driver is not a string',
                [
                    $this->createIssue(
                        message: 'Session driver is not a string',
                        location: $this->getConfigLocation(),
                        severity: Severity::Critical,
                        recommendation: 'Set the session driver to one of the session drivers Laravel supports. Laravel cannot build a session store from a non-string driver, so every request that touches the session fails at runtime.',
                        metadata: ['type' => get_debug_type($driver), 'environment' => $environment]
                    ),
                ]
            );
        }

        // Assess the driver based on environment
        $issue = $this->assessDriver($driver, $environment);
        $issues = $issue !== null ? [$issue] : [];

        $message = empty($issues)
            ? "Session driver '$driver' is properly configured for $environment environment"
            : "Session driver '$driver' has configuration issues";

        return $this->resultBySeverity($message, $issues);
    }

    /**
     * Assess a session driver and return an issue if problematic.
     */
    private function assessDriver(string $driver, string $environment): ?Issue
    {
        return match ($driver) {
            'null' => $this->assessNullDriver($environment),
            'array' => $this->assessArrayDriver($environment),
            'file' => $this->assessFileDriver($environment),
            'cookie' => $this->assessCookieDriver($environment),
            default => null, // redis, database, memcached, dynamodb are all fine
        };
    }

    /**
     * Assess null driver - sessions are completely disabled.
     */
    private function assessNullDriver(string $environment): Issue
    {
        return $this->createIssue(
            message: "Session driver is set to 'null' - sessions are disabled",
            location: $this->getConfigLocation(),
            severity: Severity::Critical,
            recommendation: 'Null driver disables sessions completely. All session operations will fail. If you have routes using session middleware, this will cause errors. Use redis, database, or file driver instead.',
            metadata: [
                'driver' => 'null',
                'environment' => $environment,
                'uses_sessions' => true,
            ]
        );
    }

    /**
     * Assess array driver - sessions lost after request.
     */
    private function assessArrayDriver(string $environment): ?Issue
    {
        if ($this->isLocalEnvironment($environment)) {
            return null; // Acceptable in local
        }

        return $this->createIssue(
            message: "Session driver is set to 'array' in $environment environment",
            location: $this->getConfigLocation(),
            severity: Severity::Critical,
            recommendation: 'Array driver stores sessions in memory and they are lost after the request. This is only suitable for testing. Use redis, database, or file for production.',
            metadata: [
                'driver' => 'array',
                'environment' => $environment,
            ]
        );
    }

    /**
     * Assess file driver - problematic in multi-server setups.
     */
    private function assessFileDriver(string $environment): ?Issue
    {
        if ($this->isLocalEnvironment($environment)) {
            return null; // Perfectly fine for local dev
        }

        return $this->createIssue(
            message: "Session driver is set to 'file' in $environment environment",
            location: $this->getConfigLocation(),
            severity: Severity::Medium,
            recommendation: 'For load-balanced or multi-server environments, use redis or database driver to share sessions across servers. File sessions can cause users to be logged out when requests hit different servers.',
            metadata: [
                'driver' => 'file',
                'environment' => $environment,
            ]
        );
    }

    /**
     * Assess cookie driver - size limitations and security concerns.
     */
    private function assessCookieDriver(string $environment): ?Issue
    {
        if ($this->isLocalEnvironment($environment)) {
            return null; // Fine for local development
        }

        return $this->createIssue(
            message: "Session driver is set to 'cookie' in $environment environment",
            location: $this->getConfigLocation(),
            severity: Severity::Low,
            recommendation: 'Cookie driver stores all session data in encrypted cookies. This has a 4KB size limit and every request sends all session data. For better performance and security, consider using redis or database driver.',
            metadata: [
                'driver' => 'cookie',
                'environment' => $environment,
            ]
        );
    }

    /**
     * Check if environment is local/development.
     */
    private function isLocalEnvironment(string $environment): bool
    {
        return in_array($environment, ['local', 'development', 'testing'], true);
    }

    /**
     * Get the location of the session driver configuration.
     *
     * The driver comes from the config repository, which merges the framework's own
     * config/session.php, so the verdict holds whether or not the app published the
     * file - and Laravel 11+ invites deleting config files you do not customise. Only
     * the line reference is lost, so an unpublished file yields no location rather than
     * naming a file the reader cannot open.
     */
    private function getConfigLocation(): ?Location
    {
        $basePath = $this->getBasePath();
        $configPath = ConfigFileHelper::getConfigPath(
            $basePath,
            'session.php',
            fn ($file) => function_exists('config_path') ? config_path($file) : null
        );

        if (! file_exists($configPath)) {
            return null;
        }

        return new Location(
            $this->getRelativePath($configPath),
            ConfigFileHelper::findKeyLine($configPath, 'driver')
        );
    }
}
