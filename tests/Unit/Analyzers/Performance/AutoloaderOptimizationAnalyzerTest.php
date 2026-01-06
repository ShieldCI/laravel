<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as Config;
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

    public function test_passes_when_static_file_exists_even_with_empty_classmap(): void
    {
        $envContent = 'APP_ENV=production';

        // Valid optimization: autoload_static.php exists with ComposerStaticInit class
        // Empty classmap is fine for pure PSR-4 applications
        $staticContent = <<<'PHP'
<?php
class ComposerStaticInit {
    public static $classMap = [
        'Illuminate\\Foundation\\Application' => __DIR__.'/../../vendor/laravel/framework/src/Illuminate/Foundation/Application.php',
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
            'vendor/composer/autoload_static.php' => $staticContent,
            'vendor/composer/autoload_classmap.php' => <<<'PHP'
<?php
return [];
PHP,
            'vendor/composer/autoload_real.php' => $authoritativeContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass: static file exists (optimized) and authoritative mode enabled
        $this->assertPassed($result);
    }

    public function test_warns_when_optimized_with_only_vendor_entries_but_not_authoritative(): void
    {
        $envContent = 'APP_ENV=production';

        $vendorOnlyClassmap = <<<'PHP'
<?php
return [
    'Composer\\Autoload\\ClassLoader' => __DIR__.'/../../vendor/composer/ClassLoader.php',
];
PHP;

        // Valid static file indicating optimization
        $staticContent = <<<'PHP'
<?php
namespace Composer\Autoload;

class ComposerStaticInit {
    public static $prefixLengthsPsr4 = [];
    public static $prefixDirsPsr4 = [];
}
PHP;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'vendor/autoload.php' => '<?php // Autoloader',
            'vendor/composer/autoload_classmap.php' => $vendorOnlyClassmap,
            'vendor/composer/autoload_static.php' => $staticContent,
            'vendor/composer/autoload_real.php' => '<?php // No authoritative',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should warn: optimized (has static file) but not authoritative
        $this->assertWarning($result);
        $this->assertHasIssueContaining('authoritative', $result);
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

        $this->assertWarning($result);
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
        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('shieldci.environment_mapping', [
            'production-us' => 'production',
        ]);
        $config->set('app.env', 'production-us');

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
        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('shieldci.environment_mapping', [
            'production-1' => 'production',
        ]);
        $config->set('app.env', 'production-1');

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
        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('shieldci.environment_mapping', [
            'staging-preview' => 'staging',
        ]);
        $config->set('app.env', 'staging-preview');

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
        /** @var Config $config */
        $config = $this->app?->make('config') ?? app('config');
        $config->set('app.env', 'demo');

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

    public function test_fails_when_classmap_file_missing_in_production(): void
    {
        $envContent = 'APP_ENV=production';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'vendor/autoload.php' => '<?php // Autoloader',
            // No autoload_classmap.php file
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not optimized', $result);
    }

    public function test_fails_when_classmap_returns_non_array(): void
    {
        $envContent = 'APP_ENV=production';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'vendor/autoload.php' => '<?php // Autoloader',
            'vendor/composer/autoload_classmap.php' => '<?php return "not an array";',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not optimized', $result);
    }

    public function test_handles_non_string_paths_in_classmap(): void
    {
        $envContent = 'APP_ENV=production';

        // Setup optimized autoloader with static classmap
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
            'vendor/composer/autoload_real.php' => $authoritativeContent,
            'app/ValidClass.php' => '<?php namespace App; class ValidClass {}',
        ]);

        // Create classmap with non-string values (should be skipped gracefully)
        $classmap = <<<PHP
<?php
return [
    'App\\\\ValidClass' => '{$tempDir}/app/ValidClass.php',
    'InvalidClass' => null,
    'EmptyClass' => '',
    'ArrayClass' => [],
];
PHP;

        file_put_contents($tempDir.'/vendor/composer/autoload_classmap.php', $classmap);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass because ValidClass is a project class (non-string values are skipped)
        $this->assertPassed($result);
    }

    public function test_handles_windows_paths_with_drive_letters(): void
    {
        $envContent = 'APP_ENV=production';

        // Setup optimized autoloader
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
            'vendor/composer/autoload_real.php' => $authoritativeContent,
            'app/MyClass.php' => '<?php namespace App; class MyClass {}',
        ]);

        // Create Windows-style path with backslashes
        $windowsPath = str_replace('/', '\\', $tempDir.'\\app\\MyClass.php');

        $classmap = <<<PHP
<?php
return [
    'App\\\\MyClass' => '{$windowsPath}',
];
PHP;

        file_put_contents($tempDir.'/vendor/composer/autoload_classmap.php', $classmap);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass (Windows-style backslashes are normalized)
        $this->assertPassed($result);
    }

    public function test_handles_paths_with_parent_directory_references(): void
    {
        $envContent = 'APP_ENV=production';

        // Setup optimized autoloader
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
            'vendor/composer/autoload_real.php' => $authoritativeContent,
            'app/MyClass.php' => '<?php namespace App; class MyClass {}',
        ]);

        // Use path with .. references that resolves back to app/MyClass.php
        $classmap = <<<PHP
<?php
return [
    'App\\\\MyClass' => '{$tempDir}/vendor/../app/MyClass.php',
];
PHP;

        file_put_contents($tempDir.'/vendor/composer/autoload_classmap.php', $classmap);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass (path normalization handles .. and resolves to existing file)
        $this->assertPassed($result);
    }

    public function test_fails_when_only_manual_classmap_entries_without_static_file(): void
    {
        $envContent = 'APP_ENV=production';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'vendor/autoload.php' => '<?php // Autoloader',
            'vendor/composer/autoload_classmap.php' => <<<'PHP'
<?php
return [
    'App\\MyClass' => __DIR__.'/../../app/MyClass.php',
];
PHP,
            // No autoload_static.php - means no optimization, just manual classmap entries
            // No autoload_real.php
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail: having project classes in classmap without autoload_static.php
        // means these are manual classmap entries, not optimization
        $this->assertFailed($result);
        $this->assertHasIssueContaining('not optimized', $result);

        $issues = $result->getIssues();
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::High, $issues[0]->severity);
    }

    public function test_handles_invalid_composer_json(): void
    {
        $envContent = 'APP_ENV=production';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'composer.json' => '{invalid json',
            'vendor/autoload.php' => '<?php // Autoloader',
            'vendor/composer/autoload_classmap.php' => <<<'PHP'
<?php
return [];
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail (not optimized, but won't crash on invalid JSON)
        $this->assertFailed($result);
        $this->assertHasIssueContaining('not optimized', $result);
    }

    public function test_handles_non_array_config_in_composer_json(): void
    {
        $envContent = 'APP_ENV=production';

        $composerJson = json_encode([
            'config' => 'invalid',
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

        // Should fail gracefully (treats as no config)
        $this->assertFailed($result);
        $this->assertHasIssueContaining('not optimized', $result);

        $issues = $result->getIssues();
        $this->assertFalse($issues[0]->metadata['configured_optimize']);
    }

    public function test_handles_invalid_script_command_types(): void
    {
        $envContent = 'APP_ENV=production';

        $composerJson = json_encode([
            'scripts' => [
                'post-install-cmd' => 123,
                'post-update-cmd' => null,
                'pre-install-cmd' => false,
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

        // Should handle gracefully (invalid script types are ignored)
        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertFalse($issues[0]->metadata['configured_via_scripts']);
    }

    public function test_detects_composer_update_with_optimization(): void
    {
        $envContent = 'APP_ENV=production';

        $composerJson = json_encode([
            'scripts' => [
                'post-update-cmd' => 'composer update --optimize-autoloader',
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

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertTrue($issues[0]->metadata['configured_via_scripts']);
    }

    public function test_handles_authoritative_config_without_optimize(): void
    {
        $envContent = 'APP_ENV=production';

        $composerJson = json_encode([
            'config' => [
                'classmap-authoritative' => true,
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

        // Should fail (authoritative config but not actually optimized)
        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertFalse($issues[0]->metadata['configured_optimize']);
        $this->assertTrue($issues[0]->metadata['configured_authoritative']);
    }

    public function test_detects_multiple_optimization_flags_in_script(): void
    {
        $envContent = 'APP_ENV=production';

        $composerJson = json_encode([
            'scripts' => [
                'post-install-cmd' => 'composer dump-autoload -o --classmap-authoritative',
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

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertTrue($issues[0]->metadata['configured_via_scripts']);
    }

    public function test_detects_short_flag_optimization_in_scripts(): void
    {
        $envContent = 'APP_ENV=production';

        $composerJson = json_encode([
            'scripts' => [
                'post-install-cmd' => 'composer dump-autoload -o',
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

        $issues = $result->getIssues();
        $this->assertTrue($issues[0]->metadata['configured_via_scripts']);
    }

    public function test_handles_mixed_slash_paths_in_classmap(): void
    {
        $envContent = 'APP_ENV=production';

        // Setup optimized autoloader
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
            'vendor/composer/autoload_real.php' => $authoritativeContent,
            'app/MyClass.php' => '<?php namespace App; class MyClass {}',
        ]);

        // Create path with mixed slashes (backslashes and forward slashes)
        $mixedPath = str_replace('/', '\\', $tempDir).'\\app/MyClass.php';

        $classmap = <<<PHP
<?php
return [
    'App\\\\MyClass' => '{$mixedPath}',
];
PHP;

        file_put_contents($tempDir.'/vendor/composer/autoload_classmap.php', $classmap);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass (path normalization handles mixed slashes and file exists)
        $this->assertPassed($result);
    }

    public function test_handles_paths_with_dot_segments(): void
    {
        $envContent = 'APP_ENV=production';

        // Setup optimized autoloader
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
            'vendor/composer/autoload_real.php' => $authoritativeContent,
            'app/MyClass.php' => '<?php namespace App; class MyClass {}',
        ]);

        // Use path with . segments (current directory references)
        $classmap = <<<PHP
<?php
return [
    'App\\\\MyClass' => '{$tempDir}/./app/./MyClass.php',
];
PHP;

        file_put_contents($tempDir.'/vendor/composer/autoload_classmap.php', $classmap);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass (path normalization handles . segments and file exists)
        $this->assertPassed($result);
    }

    public function test_fails_when_scripts_config_is_non_array(): void
    {
        $envContent = 'APP_ENV=production';

        $composerJson = json_encode([
            'scripts' => 'not an array',
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

        // Should fail gracefully (non-array scripts treated as empty)
        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertFalse($issues[0]->metadata['configured_via_scripts']);
    }
}
