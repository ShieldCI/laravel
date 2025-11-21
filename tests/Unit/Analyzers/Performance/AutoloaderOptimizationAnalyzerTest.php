<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use ShieldCI\Analyzers\Performance\AutoloaderOptimizationAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class AutoloaderOptimizationAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new AutoloaderOptimizationAnalyzer;
    }

    public function test_skips_in_local_environment(): void
    {
        $envContent = 'APP_ENV=local';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'vendor/autoload.php' => '<?php // Autoloader',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should skip in local environment (not relevant)
        $this->assertSkipped($result);
        $this->assertStringContainsString('local', $result->getMessage());
        $this->assertStringContainsString('production', $result->getMessage());
    }

    public function test_runs_in_production_environment(): void
    {
        $envContent = 'APP_ENV=production';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'vendor/autoload.php' => '<?php // Autoloader',
            'vendor/composer/autoload_static.php' => '<?php class ComposerAutoloaderInit {}',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should run in production (relevant environment)
        $this->assertNotEquals('skipped', $result->getStatus()->value);
    }

    public function test_runs_in_staging_environment(): void
    {
        $envContent = 'APP_ENV=staging';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'vendor/autoload.php' => '<?php // Autoloader',
            'vendor/composer/autoload_static.php' => '<?php class ComposerAutoloaderInit {}',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should run in staging (relevant environment)
        $this->assertNotEquals('skipped', $result->getStatus()->value);
    }

    public function test_skips_when_vendor_not_found_in_production(): void
    {
        $envContent = 'APP_ENV=production';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
        $this->assertStringContainsString('vendor directory', $result->getMessage());
    }

    public function test_fails_when_autoloader_not_optimized_in_production(): void
    {
        $envContent = 'APP_ENV=production';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'vendor/autoload.php' => '<?php // Autoloader',
            'vendor/composer/autoload_static.php' => '<?php // No optimization',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not optimized', $result);
    }

    public function test_fails_when_generated_classmap_is_empty_even_if_static_contains_laravel_classes(): void
    {
        $envContent = 'APP_ENV=production';

        $staticContent = <<<'PHP'
<?php
class ComposerAutoloaderInit {
    public static $classMap = [
        'Illuminate\\Foundation\\Application' => __DIR__.'/../../vendor/laravel/framework/src/Illuminate/Foundation/Application.php',
    ];
}
PHP;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'vendor/autoload.php' => '<?php // Autoloader',
            'vendor/composer/autoload_static.php' => $staticContent,
            'vendor/composer/autoload_classmap.php' => <<<'PHP'
<?php
return [];
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not optimized', $result);
    }

    public function test_fails_when_classmap_contains_only_vendor_entries(): void
    {
        $envContent = 'APP_ENV=production';

        $vendorOnlyClassmap = <<<'PHP'
<?php
return [
    'Composer\\Autoload\\ClassLoader' => __DIR__.'/../../vendor/composer/ClassLoader.php',
];
PHP;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'vendor/autoload.php' => '<?php // Autoloader',
            'vendor/composer/autoload_classmap.php' => $vendorOnlyClassmap,
            'vendor/composer/autoload_static.php' => '<?php class ComposerAutoloaderInit {}',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not optimized', $result);
    }

    public function test_reports_when_config_enables_optimize_without_optimized_files(): void
    {
        $envContent = 'APP_ENV=production';

        $composerJson = json_encode([
            'config' => [
                'optimize-autoloader' => true,
            ],
        ], JSON_PRETTY_PRINT);

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'composer.json' => $composerJson,
            'vendor/autoload.php' => '<?php // Autoloader',
            'vendor/composer/autoload_classmap.php' => <<<'PHP'
<?php
return [];
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('config enables "optimize-autoloader"', $result);
    }

    public function test_detects_composer_scripts_with_optimization_flags(): void
    {
        $envContent = 'APP_ENV=production';

        $composerJson = json_encode([
            'scripts' => [
                'post-install-cmd' => [
                    'composer dump-autoload -o',
                ],
                'post-update-cmd' => [
                    'composer install --optimize-autoloader',
                ],
            ],
        ], JSON_PRETTY_PRINT);

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'composer.json' => $composerJson,
            'vendor/autoload.php' => '<?php // Autoloader',
            'vendor/composer/autoload_classmap.php' => <<<'PHP'
<?php
return [];
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $firstIssue = $issues[0];
        $this->assertArrayHasKey('configured_via_scripts', $firstIssue->metadata);
        $this->assertTrue($firstIssue->metadata['configured_via_scripts']);
    }

    public function test_recommends_authoritative_when_optimized_but_not_authoritative(): void
    {
        $envContent = 'APP_ENV=production';

        // Simulate optimized but not authoritative
        $optimizedContent = <<<'PHP'
<?php
class ComposerAutoloaderInit {
    public static $classMap = [
        'Illuminate\\Foundation\\Application' => '/path/to/file.php',
    ];
}
PHP;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'vendor/autoload.php' => '<?php // Autoloader',
            'vendor/composer/autoload_static.php' => $optimizedContent,
            'vendor/composer/autoload_classmap.php' => <<<'PHP'
<?php
return [
    'App\\Providers\\AppServiceProvider' => __DIR__.'/../../app/Providers/AppServiceProvider.php',
];
PHP,
            'vendor/composer/autoload_real.php' => '<?php // No authoritative',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('authoritative', $result);
    }

    public function test_passes_when_fully_optimized_with_authoritative(): void
    {
        $envContent = 'APP_ENV=production';

        // Simulate optimized with authoritative
        $optimizedContent = <<<'PHP'
<?php
class ComposerAutoloaderInit {
    public static $classMap = [
        'Illuminate\\Foundation\\Application' => '/path/to/file.php',
    ];
}
PHP;

        $authoritativeContent = <<<'PHP'
<?php
$loader->setClassMapAuthoritative(true);
PHP;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'vendor/autoload.php' => '<?php // Autoloader',
            'vendor/composer/autoload_static.php' => $optimizedContent,
            'vendor/composer/autoload_classmap.php' => <<<'PHP'
<?php
return [
    'App\\Providers\\AppServiceProvider' => __DIR__.'/../../app/Providers/AppServiceProvider.php',
];
PHP,
            'vendor/composer/autoload_real.php' => $authoritativeContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skip_reason_mentions_environment_when_not_relevant(): void
    {
        $envContent = 'APP_ENV=local';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'vendor/autoload.php' => '<?php // Autoloader',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);

        // Skip message should clearly state why
        $message = $result->getMessage();
        $this->assertStringContainsString('local', $message);
        $this->assertStringContainsString('production', $message);
        $this->assertStringContainsString('staging', $message);
    }

    public function test_skips_in_development_environment(): void
    {
        $envContent = 'APP_ENV=development';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'vendor/autoload.php' => '<?php // Autoloader',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
        $this->assertStringContainsString('development', $result->getMessage());
    }

    public function test_skips_in_testing_environment(): void
    {
        $envContent = 'APP_ENV=testing';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'vendor/autoload.php' => '<?php // Autoloader',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
        $this->assertStringContainsString('testing', $result->getMessage());
    }

    public function test_runs_in_production_us_variant_with_mapping(): void
    {
        // Configure environment mapping
        config()->set('shieldci.environment_mapping', [
            'production-us' => 'production',
        ]);
        config()->set('app.env', 'production-us');

        $tempDir = $this->createTempDirectory([
            'vendor/autoload.php' => '<?php // Autoloader',
            'vendor/composer/autoload_static.php' => '<?php class ComposerAutoloaderInit {}',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should run (production-us maps to production)
        $this->assertNotEquals('skipped', $result->getStatus()->value);
    }

    public function test_runs_in_production_1_variant_with_mapping(): void
    {
        // Configure environment mapping
        config()->set('shieldci.environment_mapping', [
            'production-1' => 'production',
        ]);
        config()->set('app.env', 'production-1');

        $tempDir = $this->createTempDirectory([
            'vendor/autoload.php' => '<?php // Autoloader',
            'vendor/composer/autoload_static.php' => '<?php class ComposerAutoloaderInit {}',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should run (production-1 maps to production)
        $this->assertNotEquals('skipped', $result->getStatus()->value);
    }

    public function test_runs_in_staging_preview_variant_with_mapping(): void
    {
        // Configure environment mapping
        config()->set('shieldci.environment_mapping', [
            'staging-preview' => 'staging',
        ]);
        config()->set('app.env', 'staging-preview');

        $tempDir = $this->createTempDirectory([
            'vendor/autoload.php' => '<?php // Autoloader',
            'vendor/composer/autoload_static.php' => '<?php class ComposerAutoloaderInit {}',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should run (staging-preview maps to staging)
        $this->assertNotEquals('skipped', $result->getStatus()->value);
    }

    public function test_skips_in_demo_environment_without_mapping(): void
    {
        // No environment mapping configured for 'demo'
        config()->set('app.env', 'demo');

        $tempDir = $this->createTempDirectory([
            'vendor/autoload.php' => '<?php // Autoloader',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should skip (demo doesn't map to production or staging)
        $this->assertSkipped($result);
        $this->assertStringContainsString('demo', $result->getMessage());
    }
}
