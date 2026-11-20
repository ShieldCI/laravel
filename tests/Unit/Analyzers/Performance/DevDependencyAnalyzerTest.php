<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Foundation\Application as LaravelApplication;
use PHPUnit\Framework\Attributes\DataProvider;
use ShieldCI\Analyzers\Performance\DevDependencyAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class DevDependencyAnalyzerTest extends AnalyzerTestCase
{
    private ?string $originalPath = null;

    protected function tearDown(): void
    {
        if ($this->originalPath !== null) {
            putenv('PATH='.$this->originalPath);
            $this->originalPath = null;
        }

        parent::tearDown();
    }

    protected function createAnalyzer(): AnalyzerInterface
    {
        return new DevDependencyAnalyzer;
    }

    public function test_fails_when_composer_lock_missing(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{}',
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'production');
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $analyzer = $this->createAnalyzer();
            $result = $analyzer->analyze();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        $this->assertFailed($result);
        $this->assertHasIssueContaining('composer.lock file not found', $result);
    }

    public function test_detects_dev_packages_via_filesystem(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [],
    "packages-dev": [
        {"name": "phpunit/phpunit"},
        {"name": "fakerphp/faker"}
    ]
}
JSON;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{}',
            'composer.lock' => $composerLock,
            'vendor/autoload.php' => '<?php',
            'vendor/phpunit/phpunit/composer.json' => '{}',
            'vendor/fakerphp/faker/composer.json' => '{}',
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'production');
        $analyzer = new class extends DevDependencyAnalyzer
        {
            protected function isComposerAvailable(): bool
            {
                return false;
            }
        };
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $result = $analyzer->analyze();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Found 2 dev dependencies installed', $result);
        $issues = $result->getIssues();
        $this->assertSame('file_system', $issues[0]->metadata['detection_method'] ?? null);
    }

    // Critical Untested Cases

    public function test_passes_when_no_dev_packages_installed(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [{"name": "symfony/console"}],
    "packages-dev": []
}
JSON;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{}',
            'composer.lock' => $composerLock,
            'vendor/autoload.php' => '<?php',
            'vendor/symfony/console/composer.json' => '{}',
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'production');
        $analyzer = new class extends DevDependencyAnalyzer
        {
            protected function isComposerAvailable(): bool
            {
                return false;
            }
        };
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $result = $analyzer->analyze();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        $this->assertPassed($result);
        $this->assertStringContainsString('No dev dependencies detected', $result->getMessage());
    }

    public function test_skips_in_local_environment(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=local',
            'composer.json' => '{}',
            'composer.lock' => '{}',
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'local');
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $analyzer = $this->createAnalyzer();
            $shouldRun = $analyzer->shouldRun();
            $skipReason = $analyzer->getSkipReason();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        $this->assertFalse($shouldRun);
        $this->assertStringContainsString('local', $skipReason);
        $this->assertStringContainsString('production, staging', $skipReason);
    }

    public function test_skips_in_development_environment(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=development',
            'composer.json' => '{}',
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'development');
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $analyzer = $this->createAnalyzer();
            $shouldRun = $analyzer->shouldRun();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        $this->assertFalse($shouldRun);
    }

    public function test_skips_in_testing_environment(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=testing',
            'composer.json' => '{}',
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'testing');
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $analyzer = $this->createAnalyzer();
            $shouldRun = $analyzer->shouldRun();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        $this->assertFalse($shouldRun);
    }

    public function test_runs_in_staging_environment(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=staging',
            'composer.json' => '{}',
            'composer.lock' => '{"packages":[],"packages-dev":[]}',
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'staging');
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $analyzer = new class extends DevDependencyAnalyzer
            {
                protected function isComposerAvailable(): bool
                {
                    return false;
                }
            };
            $result = $analyzer->analyze();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        $this->assertPassed($result);
    }

    public function test_skips_when_composer_json_missing(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'production');
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $analyzer = $this->createAnalyzer();
            $shouldRun = $analyzer->shouldRun();
            $skipReason = $analyzer->getSkipReason();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        $this->assertFalse($shouldRun);
        $this->assertStringContainsString('composer.json', $skipReason);
    }

    public function test_handles_missing_vendor_directory(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [],
    "packages-dev": [{"name": "phpunit/phpunit"}]
}
JSON;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{}',
            'composer.lock' => $composerLock,
            // No vendor directory
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'production');
        $analyzer = new class extends DevDependencyAnalyzer
        {
            protected function isComposerAvailable(): bool
            {
                return false;
            }
        };
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $result = $analyzer->analyze();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        // No vendor directory means no packages installed
        $this->assertPassed($result);
    }

    public function test_handles_empty_vendor_directory(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [],
    "packages-dev": [{"name": "phpunit/phpunit"}]
}
JSON;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{}',
            'composer.lock' => $composerLock,
            'vendor/.gitkeep' => '',
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'production');
        $analyzer = new class extends DevDependencyAnalyzer
        {
            protected function isComposerAvailable(): bool
            {
                return false;
            }
        };
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $result = $analyzer->analyze();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        // Dev package not actually installed in vendor
        $this->assertPassed($result);
    }

    public function test_handles_malformed_composer_lock_json(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{"require-dev":{"phpunit/phpunit":"^10.0"}}',
            'composer.lock' => '{invalid json',
            'vendor/phpunit/phpunit/composer.json' => '{}',
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'production');
        $analyzer = new class extends DevDependencyAnalyzer
        {
            protected function isComposerAvailable(): bool
            {
                return false;
            }
        };
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $result = $analyzer->analyze();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        // Falls back to composer.json parsing
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Found 1 dev dependencies installed', $result);
    }

    public function test_handles_composer_lock_missing_packages_dev_key(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [{"name": "symfony/console"}]
}
JSON;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{}',
            'composer.lock' => $composerLock,
            'vendor/symfony/console/composer.json' => '{}',
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'production');
        $analyzer = new class extends DevDependencyAnalyzer
        {
            protected function isComposerAvailable(): bool
            {
                return false;
            }
        };
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $result = $analyzer->analyze();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        $this->assertPassed($result);
    }

    public function test_handles_composer_lock_packages_dev_null(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [],
    "packages-dev": null
}
JSON;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{}',
            'composer.lock' => $composerLock,
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'production');
        $analyzer = new class extends DevDependencyAnalyzer
        {
            protected function isComposerAvailable(): bool
            {
                return false;
            }
        };
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $result = $analyzer->analyze();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        $this->assertPassed($result);
    }

    public function test_handles_composer_lock_with_non_array_items(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [],
    "packages-dev": [
        null,
        "string",
        123,
        {"name": "phpunit/phpunit"}
    ]
}
JSON;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{}',
            'composer.lock' => $composerLock,
            'vendor/phpunit/phpunit/composer.json' => '{}',
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'production');
        $analyzer = new class extends DevDependencyAnalyzer
        {
            protected function isComposerAvailable(): bool
            {
                return false;
            }
        };
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $result = $analyzer->analyze();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        // Should filter out non-array items and process valid package
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Found 1 dev dependencies', $result);
    }

    public function test_handles_composer_lock_package_missing_name_field(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [],
    "packages-dev": [
        {"version": "1.0"},
        {"name": "phpunit/phpunit"}
    ]
}
JSON;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{}',
            'composer.lock' => $composerLock,
            'vendor/phpunit/phpunit/composer.json' => '{}',
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'production');
        $analyzer = new class extends DevDependencyAnalyzer
        {
            protected function isComposerAvailable(): bool
            {
                return false;
            }
        };
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $result = $analyzer->analyze();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        // Should skip package without name
        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
    }

    public function test_handles_malformed_composer_json(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{invalid',
            'composer.lock' => '{"packages":[],"packages-dev":[]}',
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'production');
        $analyzer = new class extends DevDependencyAnalyzer
        {
            protected function isComposerAvailable(): bool
            {
                return false;
            }
        };
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $result = $analyzer->analyze();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        // Can't parse composer.json, but lock file shows no dev deps
        $this->assertPassed($result);
    }

    public function test_handles_composer_json_require_dev_null(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [],
    "packages-dev": []
}
JSON;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{"require-dev":null}',
            'composer.lock' => $composerLock,
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'production');
        $analyzer = new class extends DevDependencyAnalyzer
        {
            protected function isComposerAvailable(): bool
            {
                return false;
            }
        };
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $result = $analyzer->analyze();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        $this->assertPassed($result);
    }

    public function test_handles_composer_json_require_dev_empty(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [],
    "packages-dev": []
}
JSON;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{"require-dev":{}}',
            'composer.lock' => $composerLock,
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'production');
        $analyzer = new class extends DevDependencyAnalyzer
        {
            protected function isComposerAvailable(): bool
            {
                return false;
            }
        };
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $result = $analyzer->analyze();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        $this->assertPassed($result);
    }

    public function test_handles_package_names_with_dots(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [],
    "packages-dev": [
        {"name": "symfony/polyfill-php8.0"},
        {"name": "doctrine/dbal-2.0"}
    ]
}
JSON;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{}',
            'composer.lock' => $composerLock,
            'vendor/symfony/polyfill-php8.0/composer.json' => '{}',
            'vendor/doctrine/dbal-2.0/composer.json' => '{}',
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'production');
        $analyzer = new class extends DevDependencyAnalyzer
        {
            protected function isComposerAvailable(): bool
            {
                return false;
            }
        };
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $result = $analyzer->analyze();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Found 2 dev dependencies', $result);
    }

    public function test_limits_package_list_to_ten(): void
    {
        $packages = [];
        $vendorFiles = [
            '.env' => 'APP_ENV=production',
            'composer.json' => '{}',
        ];

        for ($i = 1; $i <= 15; $i++) {
            $packages[] = sprintf('{"name": "vendor/package-%d"}', $i);
            $vendorFiles["vendor/vendor/package-{$i}/composer.json"] = '{}';
        }

        $composerLock = sprintf('{"packages":[],"packages-dev":[%s]}', implode(',', $packages));
        $vendorFiles['composer.lock'] = $composerLock;

        $tempDir = $this->createTempDirectory($vendorFiles);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'production');
        $analyzer = new class extends DevDependencyAnalyzer
        {
            protected function isComposerAvailable(): bool
            {
                return false;
            }
        };
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $result = $analyzer->analyze();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $installedPackages = $issues[0]->metadata['installed_dev_packages'] ?? [];
        $this->assertIsArray($installedPackages);
        $this->assertCount(10, $installedPackages); // Limited to 10
        $this->assertEquals(15, $issues[0]->metadata['total_count'] ?? 0); // But total is 15
    }

    public function test_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertEquals('dev-dependencies-production', $metadata->id);
        $this->assertEquals('Dev Dependencies in Production Analyzer', $metadata->name);
        $this->assertEquals(Category::Performance, $metadata->category);
        $this->assertEquals(Severity::High, $metadata->severity);
        $this->assertContains('composer', $metadata->tags);
        $this->assertContains('performance', $metadata->tags);
    }

    public function test_run_in_ci_property_is_false(): void
    {
        $this->assertFalse(DevDependencyAnalyzer::$runInCI);
    }

    public function test_relevant_environments(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{}',
            'composer.lock' => '{"packages":[],"packages-dev":[]}',
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'production');
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $analyzer = new class extends DevDependencyAnalyzer
            {
                protected function isComposerAvailable(): bool
                {
                    return false;
                }
            };
            $result = $analyzer->analyze();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        $this->assertPassed($result);
    }

    public function test_recommendation_contains_actionable_advice(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [],
    "packages-dev": [{"name": "phpunit/phpunit"}]
}
JSON;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{}',
            'composer.lock' => $composerLock,
            'vendor/phpunit/phpunit/composer.json' => '{}',
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'production');
        $analyzer = new class extends DevDependencyAnalyzer
        {
            protected function isComposerAvailable(): bool
            {
                return false;
            }
        };
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $result = $analyzer->analyze();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('--no-dev', $recommendation);
        $this->assertStringContainsString('composer install', $recommendation);
        $this->assertStringContainsString('deployment', $recommendation);
    }

    public function test_issue_has_correct_severity(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [],
    "packages-dev": [{"name": "phpunit/phpunit"}]
}
JSON;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{}',
            'composer.lock' => $composerLock,
            'vendor/phpunit/phpunit/composer.json' => '{}',
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'production');
        $analyzer = new class extends DevDependencyAnalyzer
        {
            protected function isComposerAvailable(): bool
            {
                return false;
            }
        };
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $result = $analyzer->analyze();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals(Severity::High, $issues[0]->severity);
    }

    public function test_mixed_dev_and_prod_packages(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [],
    "packages-dev": [
        {"name": "phpunit/phpunit"},
        {"name": "mockery/mockery"},
        {"name": "fakerphp/faker"}
    ]
}
JSON;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{}',
            'composer.lock' => $composerLock,
            'vendor/phpunit/phpunit/composer.json' => '{}',
            // mockery not installed
            'vendor/fakerphp/faker/composer.json' => '{}',
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'production');
        $analyzer = new class extends DevDependencyAnalyzer
        {
            protected function isComposerAvailable(): bool
            {
                return false;
            }
        };
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $result = $analyzer->analyze();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Found 2 dev dependencies', $result);

        $issues = $result->getIssues();
        $installedPackages = $issues[0]->metadata['installed_dev_packages'] ?? [];
        $this->assertIsArray($installedPackages);
        $this->assertContains('phpunit/phpunit', $installedPackages);
        $this->assertContains('fakerphp/faker', $installedPackages);
        $this->assertNotContains('mockery/mockery', $installedPackages);
    }

    public function test_detects_packages_from_composer_json_when_lock_unavailable(): void
    {
        $composerJson = <<<'JSON'
{
    "require": {"symfony/console": "^6.0"},
    "require-dev": {
        "phpunit/phpunit": "^10.0",
        "fakerphp/faker": "^1.20"
    }
}
JSON;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => $composerJson,
            // composer.lock exists but empty/malformed - falls back to composer.json
            'composer.lock' => 'null',
            'vendor/phpunit/phpunit/composer.json' => '{}',
            'vendor/fakerphp/faker/composer.json' => '{}',
        ]);

        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'production');
        $analyzer = new class extends DevDependencyAnalyzer
        {
            protected function isComposerAvailable(): bool
            {
                return false;
            }
        };
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            $result = $analyzer->analyze();
        } finally {
            $application->setBasePath($originalBasePath);
        }

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Found 2 dev dependencies', $result);
    }

    public function test_falls_back_to_filesystem_when_composer_dry_run_lists_no_removals(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [],
    "packages-dev": [
        {"name": "phpunit/phpunit"},
        {"name": "fakerphp/faker"}
    ]
}
JSON;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{"require-dev":{"phpunit/phpunit":"^11.0"}}',
            'composer.lock' => $composerLock,
            'vendor/autoload.php' => '<?php',
            'vendor/phpunit/phpunit/composer.json' => '{}',
            'vendor/fakerphp/faker/composer.json' => '{}',
        ]);

        // No vendor/composer/installed.json: composer has nothing to compare the lock against.
        $this->assertFileDoesNotExist($tempDir.'/vendor/composer/installed.json');
        $this->installComposerStub($tempDir, "#!/bin/sh\nexit 0\n");

        $result = $this->analyzeInProduction(new DevDependencyAnalyzer, $tempDir);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Found 2 dev dependencies installed', $result);
        $issues = $result->getIssues();
        $this->assertSame('file_system', $issues[0]->metadata['detection_method'] ?? null);
    }

    public function test_reports_removals_listed_by_composer_dry_run(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [],
    "packages-dev": [
        {"name": "phpunit/phpunit"}
    ]
}
JSON;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{"require-dev":{"phpunit/phpunit":"^11.0"}}',
            'composer.lock' => $composerLock,
            'vendor/autoload.php' => '<?php',
            'vendor/phpunit/phpunit/composer.json' => '{}',
        ]);

        $this->installComposerStub($tempDir, "#!/bin/sh\necho '  - Removing phpunit/phpunit (11.0.0)'\nexit 0\n");

        $result = $this->analyzeInProduction(new DevDependencyAnalyzer, $tempDir);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Dev dependencies are installed in production environment', $result);
        $issues = $result->getIssues();
        $this->assertSame('composer_dry_run', $issues[0]->metadata['detection_method'] ?? null);
        $this->assertSame(['phpunit/phpunit'], $issues[0]->metadata['packages_to_remove'] ?? null);
    }

    public function test_passes_when_composer_dry_run_lists_no_removals_and_no_dev_packages_installed(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [{"name": "symfony/console"}],
    "packages-dev": [
        {"name": "phpunit/phpunit"}
    ]
}
JSON;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{"require-dev":{"phpunit/phpunit":"^11.0"}}',
            'composer.lock' => $composerLock,
            'vendor/autoload.php' => '<?php',
            'vendor/symfony/console/composer.json' => '{}',
        ]);

        $this->installComposerStub($tempDir, "#!/bin/sh\nexit 0\n");

        $result = $this->analyzeInProduction(new DevDependencyAnalyzer, $tempDir);

        $this->assertPassed($result);
    }

    /**
     * @dataProvider vendorDirProvider
     */
    #[DataProvider('vendorDirProvider')]
    public function test_detects_dev_packages_in_configured_vendor_dir(string $vendorDir): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [],
    "packages-dev": [
        {"name": "phpunit/phpunit"}
    ]
}
JSON;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.lock' => $composerLock,
            'lib/vendor/autoload.php' => '<?php',
            'lib/vendor/phpunit/phpunit/composer.json' => '{}',
        ]);

        $composerJson = [
            'require-dev' => ['phpunit/phpunit' => '^11.0'],
            'config' => ['vendor-dir' => str_replace('{base}', $tempDir, $vendorDir)],
        ];
        file_put_contents($tempDir.'/composer.json', json_encode($composerJson, JSON_UNESCAPED_SLASHES));

        $result = $this->analyzeInProduction($this->filesystemOnlyAnalyzer(), $tempDir);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Found 1 dev dependencies installed', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function vendorDirProvider(): array
    {
        return [
            'relative' => ['lib/vendor'],
            'relative with trailing slash' => ['lib/vendor/'],
            'absolute' => ['{base}/lib/vendor'],
        ];
    }

    public function test_passes_when_configured_vendor_dir_has_no_dev_packages(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [{"name": "symfony/console"}],
    "packages-dev": [
        {"name": "phpunit/phpunit"}
    ]
}
JSON;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{"require-dev":{"phpunit/phpunit":"^11.0"},"config":{"vendor-dir":"lib/vendor"}}',
            'composer.lock' => $composerLock,
            'lib/vendor/autoload.php' => '<?php',
            'lib/vendor/symfony/console/composer.json' => '{}',
        ]);

        $result = $this->analyzeInProduction($this->filesystemOnlyAnalyzer(), $tempDir);

        $this->assertPassed($result);
    }

    public function test_uses_default_vendor_dir_when_config_has_no_vendor_dir(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [],
    "packages-dev": [
        {"name": "phpunit/phpunit"}
    ]
}
JSON;

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{"require-dev":{"phpunit/phpunit":"^11.0"},"config":{"sort-packages":true}}',
            'composer.lock' => $composerLock,
            'vendor/autoload.php' => '<?php',
            'vendor/phpunit/phpunit/composer.json' => '{}',
        ]);

        $result = $this->analyzeInProduction($this->filesystemOnlyAnalyzer(), $tempDir);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Found 1 dev dependencies installed', $result);
    }

    public function test_passes_when_installed_json_says_no_dev_but_a_stale_dev_dir_remains(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{"require-dev":{"phpunit/phpunit":"^11.0"}}',
            'composer.lock' => '{"packages":[],"packages-dev":[{"name":"phpunit/phpunit"}]}',
            'vendor/composer/installed.json' => '{"packages":[],"dev":false,"dev-package-names":[]}',
        ]);
        @mkdir($tempDir.'/vendor/phpunit/phpunit', 0755, true);

        $this->installComposerStub($tempDir, "#!/bin/sh\necho 'Nothing to install, update or remove'\nexit 0\n");

        $result = $this->analyzeInProduction(new DevDependencyAnalyzer, $tempDir);

        $this->assertPassed($result);
    }

    public function test_reads_installed_json_from_configured_vendor_dir(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{"require-dev":{"phpunit/phpunit":"^11.0"},"config":{"vendor-dir":"lib/vendor"}}',
            'composer.lock' => '{"packages":[],"packages-dev":[{"name":"phpunit/phpunit"}]}',
            'lib/vendor/composer/installed.json' => '{"packages":[],"dev":false,"dev-package-names":[]}',
            'lib/vendor/phpunit/phpunit/composer.json' => '{}',
        ]);

        $this->installComposerStub($tempDir, "#!/bin/sh\necho 'Nothing to install, update or remove'\nexit 0\n");

        $result = $this->analyzeInProduction(new DevDependencyAnalyzer, $tempDir);

        $this->assertPassed($result);
    }

    public function test_passes_when_composer_dry_run_removes_only_production_packages(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{"require-dev":{"phpunit/phpunit":"^11.0"}}',
            'composer.lock' => '{"packages":[],"packages-dev":[{"name":"phpunit/phpunit"}]}',
            'vendor/composer/installed.json' => '{"packages":[],"dev":false,"dev-package-names":[]}',
            'vendor/acme/prod/composer.json' => '{}',
        ]);

        $this->installComposerStub($tempDir, "#!/bin/sh\necho '  - Removing acme/prod (1.0.0)'\nexit 0\n");

        $result = $this->analyzeInProduction(new DevDependencyAnalyzer, $tempDir);

        $this->assertPassed($result);
    }

    public function test_reports_only_dev_packages_among_composer_dry_run_removals(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{"require-dev":{"phpunit/phpunit":"^11.0"}}',
            'composer.lock' => '{"packages":[],"packages-dev":[{"name":"phpunit/phpunit"}]}',
            'vendor/composer/installed.json' => '{"packages":[],"dev":true,"dev-package-names":["phpunit/phpunit"]}',
            'vendor/acme/prod/composer.json' => '{}',
            'vendor/phpunit/phpunit/composer.json' => '{}',
        ]);

        $this->installComposerStub(
            $tempDir,
            "#!/bin/sh\necho '  - Removing acme/prod (1.0.0)'\necho '  - Removing phpunit/phpunit (11.0.0)'\nexit 0\n"
        );

        $result = $this->analyzeInProduction(new DevDependencyAnalyzer, $tempDir);

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertSame('composer_dry_run', $issues[0]->metadata['detection_method'] ?? null);
        $this->assertSame(['phpunit/phpunit'], $issues[0]->metadata['packages_to_remove'] ?? null);
        $this->assertSame(1, $issues[0]->metadata['total_packages'] ?? null);
    }

    private function filesystemOnlyAnalyzer(): DevDependencyAnalyzer
    {
        return new class extends DevDependencyAnalyzer
        {
            protected function isComposerAvailable(): bool
            {
                return false;
            }
        };
    }

    private function analyzeInProduction(DevDependencyAnalyzer $analyzer, string $tempDir): ResultInterface
    {
        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'production');
        /** @var LaravelApplication $application */
        $application = app();
        $originalBasePath = $application->basePath();
        $application->setBasePath($tempDir);

        try {
            return $analyzer->analyze();
        } finally {
            $application->setBasePath($originalBasePath);
        }
    }

    /**
     * Puts a stub composer first on PATH so the analyzer takes its dry-run branch.
     */
    private function installComposerStub(string $tempDir, string $script): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            $this->markTestSkipped('The composer stub is a POSIX shell script.');
        }

        @mkdir($tempDir.'/bin', 0755, true);
        file_put_contents($tempDir.'/bin/composer', $script);
        chmod($tempDir.'/bin/composer', 0755);

        $this->originalPath = (string) getenv('PATH');
        putenv('PATH='.$tempDir.'/bin'.PATH_SEPARATOR.$this->originalPath);
    }
}
