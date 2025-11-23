<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use Illuminate\Foundation\Application as LaravelApplication;
use ShieldCI\Analyzers\Performance\DevDependencyAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class DevDependencyAnalyzerTest extends AnalyzerTestCase
{
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

        config()->set('app.env', 'production');
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

        config()->set('app.env', 'production');
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

        config()->set('app.env', 'production');
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

        config()->set('app.env', 'local');
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

        config()->set('app.env', 'development');
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

        config()->set('app.env', 'testing');
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

        config()->set('app.env', 'staging');
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

        config()->set('app.env', 'production');
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

        config()->set('app.env', 'production');
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

        config()->set('app.env', 'production');
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

        config()->set('app.env', 'production');
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

        config()->set('app.env', 'production');
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

        config()->set('app.env', 'production');
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

        config()->set('app.env', 'production');
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

        config()->set('app.env', 'production');
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

        config()->set('app.env', 'production');
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

        config()->set('app.env', 'production');
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

        config()->set('app.env', 'production');
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

        config()->set('app.env', 'production');
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

        config()->set('app.env', 'production');
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
        $this->assertEquals('Dev Dependencies in Production', $metadata->name);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Category::Performance, $metadata->category);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::High, $metadata->severity);
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

        config()->set('app.env', 'production');
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

        config()->set('app.env', 'production');
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

        config()->set('app.env', 'production');
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
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::High, $issues[0]->severity);
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

        config()->set('app.env', 'production');
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

        config()->set('app.env', 'production');
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
}
