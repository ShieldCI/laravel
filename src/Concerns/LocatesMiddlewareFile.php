<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

/**
 * Resolves the file in which the scanned project registers its HTTP middleware.
 */
trait LocatesMiddlewareFile
{
    /**
     * Resolve the file that registers this project's HTTP middleware, or null when the
     * project has neither candidate.
     *
     * Probes the scanned project rather than asking the running framework. Adopting the
     * Laravel 11+ skeleton was never a condition of upgrading to it, so an application on
     * Laravel 11 or later may still register middleware in app/Http/Kernel.php - which
     * means class_exists() on a framework class says nothing about where this application
     * keeps it. Naming the wrong file is not only a bad link: the accompanying advice
     * ("call $middleware->throttleWithRedis() inside withMiddleware()") does not apply to
     * a bootstrap/app.php that never calls withMiddleware().
     *
     * app/Http/Kernel.php is checked first, and that order is load-bearing: Laravel 10 and
     * earlier ship a bootstrap/app.php too - the old `new Application(...)` bootstrapper,
     * which registers no middleware - so probing bootstrap first would answer with the
     * wrong file for every Laravel 9/10 project.
     *
     * Returns an absolute path; wrap it in getRelativePath() before reporting it.
     */
    private function resolveMiddlewareFile(): ?string
    {
        $kernel = $this->buildPath('app', 'Http', 'Kernel.php');
        if (is_file($kernel)) {
            return $kernel;
        }

        $bootstrap = $this->buildPath('bootstrap', 'app.php');
        if (is_file($bootstrap)) {
            return $bootstrap;
        }

        return null;
    }

    /**
     * Whether the resolved middleware file is a Laravel 9/10 HTTP kernel.
     */
    private function middlewareFileIsHttpKernel(?string $middlewareFile): bool
    {
        return $middlewareFile !== null && str_ends_with($middlewareFile, 'Kernel.php');
    }

    /**
     * Provided by AbstractAnalyzer; declared so the trait stands on its own.
     */
    abstract protected function buildPath(string ...$segments): string;
}
