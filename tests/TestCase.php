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
        $config->set('shieldci.token', 'test-token');
        $config->set('shieldci.project_id', 'test-project-id');
        $config->set('shieldci.api_url', 'https://api.test.shieldci.com');
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
