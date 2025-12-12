<?php

declare(strict_types=1);

namespace ShieldCI\Tests;

use Illuminate\Contracts\Config\Repository as Config;
use Orchestra\Testbench\TestCase as Orchestra;
use ShieldCI\ShieldCIServiceProvider;

abstract class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();
    }

    protected function getPackageProviders($app): array
    {
        return [
            ShieldCIServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app): void
    {
        // Setup test configuration
        /** @var Config $config */
        $config = $app->make('config');
        $config->set('shieldci.enabled', true);
    }

    /**
     * Get test fixture path.
     */
    protected function getFixturePath(string $path = ''): string
    {
        return __DIR__.'/Fixtures/'.ltrim($path, '/');
    }

    /**
     * Get test stub file path.
     */
    protected function getStubPath(string $path = ''): string
    {
        return __DIR__.'/Stubs/'.ltrim($path, '/');
    }
}
