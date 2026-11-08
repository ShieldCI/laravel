<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use Illuminate\Contracts\Config\Repository as Config;
use PHPUnit\Framework\Attributes\DataProvider;
use ShieldCI\Analyzers\Performance\AutoloaderOptimizationAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
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
            ...$this->composerOutput('plain'),
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
            ...$this->composerOutput('plain'),
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
        // What plain `composer dump-autoload` writes: autoload_static.php exists with its
        // ComposerStaticInit class, but no App\ class is in the classmap.
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => $this->composerJson(),
            ...$this->composerOutput('plain'),
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not optimized', $result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(Severity::High, $issues[0]->severity);
        $this->assertFalse($issues[0]->metadata['optimized']);
    }

    public function test_fails_when_plain_dump_classmap_holds_only_vendor_classes(): void
    {
        // A dependency autoloaded through `classmap` fills the classmap in every dump mode,
        // so its size says nothing about -o: only the application's own classes do.
        $vendorClasses = [];
        for ($i = 1; $i <= 60; $i++) {
            $vendorClasses[] = "Acme\\Legacy\\Widget{$i}";
        }

        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => $this->composerJson(),
            ...$this->composerOutput('plain', classmapClasses: $vendorClasses),
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not optimized', $result);
    }

    public function test_does_not_report_unoptimized_when_no_autoload_prefixes_are_declared(): void
    {
        // Neither the root package nor any dependency declares a PSR-4/PSR-0 prefix, so the
        // classmap cannot show whether -o ran: no High issue rather than a guess.
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => $this->composerJson(psr4: []),
            ...$this->composerOutput('plain', psr4: [], projectClasses: []),
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('authoritative', $result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(Severity::Low, $issues[0]->severity);
    }

    public function test_fails_when_plain_dump_and_prefixes_come_from_autoload_psr4(): void
    {
        // No `autoload` section in composer.json: the generated autoload_psr4.php supplies
        // the prefixes to look for.
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => $this->composerJson(psr4: []),
            ...$this->composerOutput('plain'),
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not optimized', $result);
    }

    public function test_treats_optimized_dump_as_optimized_when_prefixes_come_from_autoload_psr4(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => $this->composerJson(psr4: []),
            ...$this->composerOutput('optimized'),
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('could use authoritative classmap', $result);
    }

    public function test_ignores_the_empty_psr0_fallback_prefix(): void
    {
        // A PSR-0 "" prefix matches every class name; it must not count as an application
        // prefix, so the autoload_psr4.php prefixes are used instead.
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => $this->composerJson(['autoload' => ['psr-0' => ['' => 'src/']]], psr4: []),
            ...$this->composerOutput('plain'),
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not optimized', $result);
    }

    public function test_reads_psr0_prefixes_from_composer_json(): void
    {
        $composerJson = $this->composerJson(['autoload' => ['psr-0' => ['Legacy_' => 'lib/']]], psr4: []);

        $plainDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => $composerJson,
            ...$this->composerOutput('plain', psr4: [], projectClasses: ['Legacy_Invoice']),
        ]);
        $optimizedDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => $composerJson,
            ...$this->composerOutput('optimized', psr4: [], projectClasses: ['Legacy_Invoice']),
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($plainDir);
        $plain = $analyzer->analyze();

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($optimizedDir);
        $optimized = $analyzer->analyze();

        $this->assertFailed($plain);
        $this->assertHasIssueContaining('not optimized', $plain);
        $this->assertWarning($optimized);
        $this->assertHasIssueContaining('could use authoritative classmap', $optimized);
    }

    public function test_ignores_autoload_dev_prefixes(): void
    {
        // Only the `autoload` section describes the production classes -o adds.
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => $this->composerJson(['autoload-dev' => ['psr-4' => ['Tests\\' => 'tests/']]]),
            ...$this->composerOutput('plain', classmapClasses: ['Tests\\TestCase']),
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

        $composerJson = $this->composerJson([
            'config' => [
                'optimize-autoloader' => true,
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'composer.json' => $composerJson,
            ...$this->composerOutput('plain'),
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

        $composerJson = $this->composerJson([
            'scripts' => [
                'post-install-cmd' => [
                    'composer dump-autoload -o',
                ],
                'post-update-cmd' => [
                    'composer install --optimize-autoloader',
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'composer.json' => $composerJson,
            ...$this->composerOutput('plain'),
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

    public function test_strips_a_leading_backslash_from_root_prefixes(): void
    {
        // Composer accepts "\App\" and writes the classmap keys without the leading backslash.
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => $this->composerJson(psr4: ['\\App\\' => 'app/']),
            ...$this->composerOutput('optimized'),
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('could use authoritative classmap', $result);
    }

    public function test_truncated_classmap_reads_as_not_optimized_instead_of_erroring(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => $this->composerJson(),
            ...$this->composerOutput('plain'),
            'vendor/composer/autoload_classmap.php' => "<?php\nreturn array(\n    'Acme\\\\Widget' => \n",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not optimized', $result);
    }

    public function test_truncated_autoload_psr4_leaves_the_dump_mode_undetermined_instead_of_erroring(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => $this->composerJson(psr4: []),
            ...$this->composerOutput('plain'),
            'vendor/composer/autoload_psr4.php' => "<?php\nreturn array(\n    'Acme\\\\' => array(\n",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('could use authoritative classmap', $result);
    }

    /**
     * @dataProvider wholeDirectoryExclusionProvider
     *
     * @param  array<string, string|list<string>>  $psr4
     * @param  list<string>  $excluded
     */
    #[DataProvider('wholeDirectoryExclusionProvider')]
    public function test_does_not_report_unoptimized_when_the_root_prefix_directory_is_excluded_from_the_classmap(array $psr4, array $excluded): void
    {
        // -o leaves excluded directories out of the classmap, so no App\ class can show up
        // and the autoload_psr4.php fallback must not bring the prefix back either.
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => $this->composerJson(['autoload' => [
                'psr-4' => $psr4,
                'exclude-from-classmap' => $excluded,
            ]]),
            ...$this->composerOutput('optimized', projectClasses: []),
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('could use authoritative classmap', $result);
    }

    /**
     * @return array<string, array{array<string, string|list<string>>, list<string>}>
     */
    public static function wholeDirectoryExclusionProvider(): array
    {
        return [
            'same directory' => [['App\\' => 'app/'], ['app/']],
            'dot-slash and no trailing slash' => [['App\\' => './app/'], ['app']],
            'parent directory' => [['App\\' => 'app/Domain'], ['./app/']],
            'every directory of a list' => [['App\\' => ['app/', 'modules/']], ['app', 'modules/']],
            'leading slash' => [['App\\' => 'app/'], ['/app/']],
            'recursive glob' => [['App\\' => 'app/'], ['app/**']],
            'dot-slash recursive glob' => [['App\\' => 'app/'], ['./app/**']],
            'single-level glob' => [['App\\' => 'app/'], ['app/*']],
            'dot-slash single-level glob' => [['App\\' => 'app/'], ['./app/*']],
        ];
    }

    /**
     * @dataProvider partialExclusionProvider
     *
     * @param  array<string, string|list<string>>  $psr4
     * @param  list<string>  $excluded
     */
    #[DataProvider('partialExclusionProvider')]
    public function test_still_reports_unoptimized_when_the_exclusion_does_not_cover_the_prefix(array $psr4, array $excluded): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => $this->composerJson(['autoload' => [
                'psr-4' => $psr4,
                'exclude-from-classmap' => $excluded,
            ]]),
            ...$this->composerOutput('plain'),
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not optimized', $result);
    }

    /**
     * @return array<string, array{array<string, string|list<string>>, list<string>}>
     */
    public static function partialExclusionProvider(): array
    {
        return [
            'subdirectory only' => [['App\\' => 'app/'], ['app/Legacy']],
            'sibling with a shared name prefix' => [['App\\' => 'app/'], ['application/']],
            'one directory of a list' => [['App\\' => ['app/', 'modules/']], ['app/']],
            'glob below the directory' => [['App\\' => 'app/'], ['app/*/Legacy']],
        ];
    }

    public function test_fallback_ignores_dependency_prefixes_whose_classes_ship_in_a_classmap(): void
    {
        // nette/utils and nette/schema (in every Laravel 9+ install) declare both a PSR-4
        // prefix and a `classmap`, so even a plain dump lists Nette\ classes. Only the
        // root package's own rules, under the project and outside vendor/, may stand in.
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{ not json',
            ...$this->composerOutput('plain', classmapClasses: ['Nette\\Schema\\Expect', 'Nette\\Utils\\Arrays'], vendorPsr4: self::LARAVEL_VENDOR_PSR4),
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not optimized', $result);
    }

    public function test_fallback_reads_an_optimized_dump_from_the_root_prefix_alongside_dependency_prefixes(): void
    {
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => '{ not json',
            ...$this->composerOutput('optimized', classmapClasses: ['Nette\\Schema\\Expect', 'Nette\\Utils\\Arrays'], vendorPsr4: self::LARAVEL_VENDOR_PSR4),
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('could use authoritative classmap', $result);
    }

    public function test_recommends_authoritative_when_optimized_but_not_authoritative(): void
    {
        // `composer dump-autoload -o`: the App\ classes join the classmap.
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => $this->composerJson(),
            ...$this->composerOutput('optimized'),
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('could use authoritative classmap', $result);

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(Severity::Low, $issues[0]->severity);
        $this->assertTrue($issues[0]->metadata['optimized']);
    }

    public function test_passes_when_fully_optimized_with_authoritative(): void
    {
        // `composer dump-autoload --classmap-authoritative`
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => $this->composerJson(),
            ...$this->composerOutput('authoritative'),
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
            ...$this->composerOutput('plain'),
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
            ...$this->composerOutput('plain'),
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
            ...$this->composerOutput('plain'),
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

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'composer.json' => $this->composerJson(),
            ...$this->composerOutput('authoritative'),
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

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'composer.json' => $this->composerJson(),
            ...$this->composerOutput('authoritative'),
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

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'composer.json' => $this->composerJson(),
            ...$this->composerOutput('authoritative'),
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

    public function test_fails_when_classmap_holds_only_root_classmap_entries(): void
    {
        // A root `classmap` rule (database/seeds on older skeletons) puts its classes in the
        // classmap in every dump mode; they are not the PSR-4 classes -o adds.
        $tempDir = $this->createTempDirectory([
            '.env' => 'APP_ENV=production',
            'composer.json' => $this->composerJson(['autoload' => [
                'psr-4' => ['App\\' => 'app/'],
                'classmap' => ['database/seeds'],
            ]]),
            ...$this->composerOutput('plain', classmapClasses: ['DatabaseSeeder', 'UserSeeder']),
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not optimized', $result);

        $issues = $result->getIssues();
        $this->assertEquals(Severity::High, $issues[0]->severity);
    }

    public function test_handles_invalid_composer_json(): void
    {
        $envContent = 'APP_ENV=production';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'composer.json' => '{invalid json',
            ...$this->composerOutput('plain'),
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

        $composerJson = $this->composerJson([
            'config' => 'invalid',
        ]);

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'composer.json' => $composerJson,
            ...$this->composerOutput('plain'),
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

        $composerJson = $this->composerJson([
            'scripts' => [
                'post-install-cmd' => 123,
                'post-update-cmd' => null,
                'pre-install-cmd' => false,
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'composer.json' => $composerJson,
            ...$this->composerOutput('plain'),
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

        $composerJson = $this->composerJson([
            'scripts' => [
                'post-update-cmd' => 'composer update --optimize-autoloader',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'composer.json' => $composerJson,
            ...$this->composerOutput('plain'),
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

        $composerJson = $this->composerJson([
            'config' => [
                'classmap-authoritative' => true,
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'composer.json' => $composerJson,
            ...$this->composerOutput('plain'),
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

        $composerJson = $this->composerJson([
            'scripts' => [
                'post-install-cmd' => 'composer dump-autoload -o --classmap-authoritative',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'composer.json' => $composerJson,
            ...$this->composerOutput('plain'),
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

        $composerJson = $this->composerJson([
            'scripts' => [
                'post-install-cmd' => 'composer dump-autoload -o',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'composer.json' => $composerJson,
            ...$this->composerOutput('plain'),
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

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'composer.json' => $this->composerJson(),
            ...$this->composerOutput('authoritative'),
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

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'composer.json' => $this->composerJson(),
            ...$this->composerOutput('authoritative'),
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

        $composerJson = $this->composerJson([
            'scripts' => 'not an array',
        ]);

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'composer.json' => $composerJson,
            ...$this->composerOutput('plain'),
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should fail gracefully (non-array scripts treated as empty)
        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertFalse($issues[0]->metadata['configured_via_scripts']);
    }

    public function test_detects_authoritative_with_formatting_variations(): void
    {
        $envContent = 'APP_ENV=production';

        // Test different formatting variations of setClassMapAuthoritative(true)
        $formattingVariations = [
            'setClassMapAuthoritative(true)',           // Standard
            'setClassMapAuthoritative( true )',         // Spaces inside
            'setClassMapAuthoritative (true)',          // Space before paren
            'setClassMapAuthoritative  (  true  )',     // Multiple spaces
            "setClassMapAuthoritative(\ntrue\n)",       // Newlines
            "setClassMapAuthoritative(\ttrue\t)",       // Tabs
        ];

        foreach ($formattingVariations as $variation) {
            $authoritativeContent = <<<PHP
<?php
\$loader->{$variation};
PHP;

            $tempDir = $this->createTempDirectory([
                '.env' => $envContent,
                'composer.json' => $this->composerJson(),
                ...$this->composerOutput('plain'),
                'vendor/composer/autoload_real.php' => $authoritativeContent,
            ]);

            $analyzer = $this->createAnalyzer();
            $analyzer->setBasePath($tempDir);

            $result = $analyzer->analyze();

            // Should pass for all formatting variations
            $this->assertPassed($result);
        }
    }

    public function test_ignores_echo_statements_in_scripts(): void
    {
        $envContent = 'APP_ENV=production';

        $composerJson = $this->composerJson([
            'scripts' => [
                'post-install-cmd' => [
                    "echo 'run composer dump-autoload -o later'",
                    "echo 'Remember to optimize with composer install --optimize-autoloader'",
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'composer.json' => $composerJson,
            ...$this->composerOutput('plain'),
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $firstIssue = $issues[0];
        $this->assertArrayHasKey('configured_via_scripts', $firstIssue->metadata);
        // Should be false since echo statements shouldn't count
        $this->assertFalse($firstIssue->metadata['configured_via_scripts']);
    }

    public function test_requires_composer_and_dump_autoload_in_same_command(): void
    {
        $envContent = 'APP_ENV=production';

        // These commands should NOT be detected (missing "composer" keyword)
        $composerJson = $this->composerJson([
            'scripts' => [
                'post-install-cmd' => [
                    'dump-autoload -o',  // Missing "composer" - won't match
                    './vendor/bin/dump-autoload -o',  // Custom script, not composer
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'composer.json' => $composerJson,
            ...$this->composerOutput('plain'),
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $firstIssue = $issues[0];
        $this->assertArrayHasKey('configured_via_scripts', $firstIssue->metadata);
        // Should be false since "composer" keyword is required
        $this->assertFalse($firstIssue->metadata['configured_via_scripts']);
    }

    public function test_detects_actual_composer_optimization_commands(): void
    {
        $envContent = 'APP_ENV=production';

        $composerJson = $this->composerJson([
            'scripts' => [
                'post-install-cmd' => [
                    'composer dump-autoload -o',  // Valid optimization command
                ],
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'composer.json' => $composerJson,
            ...$this->composerOutput('plain'),
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $firstIssue = $issues[0];
        $this->assertArrayHasKey('configured_via_scripts', $firstIssue->metadata);
        // Should be true - this is a real composer optimization command
        $this->assertTrue($firstIssue->metadata['configured_via_scripts']);
    }

    private const COMPOSER_HASH = '0d15ea5e0d15ea5e0d15ea5e0d15ea5e';

    private const LARAVEL_VENDOR_PSR4 = [
        'Nette\\' => ['nette/schema/src', 'nette/utils/src'],
        'Illuminate\\' => ['laravel/framework/src/Illuminate'],
    ];

    /**
     * A root composer.json whose `autoload` section declares the given PSR-4 prefixes.
     *
     * @param  array<string, mixed>  $extra  top-level keys merged over the manifest
     * @param  array<string, string|list<string>>  $psr4  namespace prefix => directories; [] omits `autoload`
     */
    private function composerJson(array $extra = [], array $psr4 = ['App\\' => 'app/']): string
    {
        $manifest = ['name' => 'acme/shop', 'require' => ['php' => '^8.2']];

        if ($psr4 !== []) {
            $manifest['autoload'] = ['psr-4' => $psr4];
        }

        return (string) json_encode(array_merge($manifest, $extra), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    /**
     * The vendor/ files `composer dump-autoload` writes, shaped like Composer 2.9 output.
     *
     * The modes differ the way Composer's do: 'optimized' (-o) and 'authoritative'
     * (--classmap-authoritative) add the PSR-4/PSR-0 classes to the classmap, and only
     * 'authoritative' calls setClassMapAuthoritative(true). Classes from `classmap` rules
     * are in the classmap in every mode.
     *
     * @param  'plain'|'optimized'|'authoritative'  $mode
     * @param  array<string, string>  $psr4  namespace prefix => directory, as autoload_psr4.php lists it
     * @param  list<string>  $projectClasses  classes under the PSR-4/PSR-0 prefixes
     * @param  list<string>  $classmapClasses  classes from `classmap` autoload rules
     * @param  array<string, list<string>>  $vendorPsr4  dependency prefix => directories under vendor/
     * @return array<string, string>
     */
    private function composerOutput(
        string $mode,
        array $psr4 = ['App\\' => 'app'],
        array $projectClasses = ['App\\Models\\User', 'App\\Providers\\AppServiceProvider'],
        array $classmapClasses = [],
        array $vendorPsr4 = [],
    ): array {
        $hash = self::COMPOSER_HASH;

        // class => [vendor-relative?, path]
        $classes = ['Composer\\InstalledVersions' => [true, '/composer/InstalledVersions.php']];

        foreach ($classmapClasses as $class) {
            $classes[$class] = [true, '/acme/legacy/src/'.str_replace('\\', '/', $class).'.php'];
        }

        if ($mode !== 'plain') {
            foreach ($projectClasses as $class) {
                $classes[$class] = [false, '/src/'.str_replace(['\\', '_'], '/', $class).'.php'];
            }
        }

        ksort($classes);

        $classmapEntries = '';
        $staticClassmapEntries = '';
        foreach ($classes as $class => [$inVendor, $path]) {
            $key = var_export($class, true);
            $classmapEntries .= "    {$key} => ".($inVendor ? '$vendorDir' : '$baseDir')." . '{$path}',\n";
            $staticClassmapEntries .= "        {$key} => __DIR__ . '".($inVendor ? '/..' : '/../..')."' . '{$path}',\n";
        }

        $psr4Entries = '';
        $prefixLengths = [];
        $prefixDirs = '';
        foreach ($psr4 as $prefix => $directory) {
            $key = var_export($prefix, true);
            $psr4Entries .= "    {$key} => array(\$baseDir . '/{$directory}'),\n";
            $prefixLengths[$prefix[0]][] = "            {$key} => ".strlen($prefix).",\n";
            $prefixDirs .= "        {$key} =>\n        array (\n            0 => __DIR__ . '/../..' . '/{$directory}',\n        ),\n";
        }

        foreach ($vendorPsr4 as $prefix => $directories) {
            $key = var_export($prefix, true);
            $psr4Entries .= "    {$key} => array(".implode(', ', array_map(static fn (string $directory): string => "\$vendorDir . '/{$directory}'", $directories))."),\n";
            $prefixLengths[$prefix[0]][] = "            {$key} => ".strlen($prefix).",\n";
            $staticDirs = '';
            foreach ($directories as $index => $directory) {
                $staticDirs .= "            {$index} => __DIR__ . '/..' . '/{$directory}',\n";
            }
            $prefixDirs .= "        {$key} =>\n        array (\n{$staticDirs}        ),\n";
        }

        $prefixLengthEntries = '';
        foreach ($prefixLengths as $letter => $entries) {
            $prefixLengthEntries .= "        '{$letter}' =>\n        array (\n".implode('', $entries)."        ),\n";
        }

        $header = static fn (string $file): string => "<?php\n\n// {$file} @generated by Composer\n\n\$vendorDir = dirname(__DIR__);\n\$baseDir = dirname(\$vendorDir);\n\n";
        $authoritative = $mode === 'authoritative' ? "        \$loader->setClassMapAuthoritative(true);\n" : '';

        return [
            'vendor/autoload.php' => "<?php\n\n// autoload.php @generated by Composer\n\nrequire_once __DIR__ . '/composer/autoload_real.php';\n\nreturn ComposerAutoloaderInit{$hash}::getLoader();\n",
            'vendor/composer/autoload_classmap.php' => $header('autoload_classmap.php')."return array(\n{$classmapEntries});\n",
            'vendor/composer/autoload_psr4.php' => $header('autoload_psr4.php')."return array(\n{$psr4Entries});\n",
            'vendor/composer/autoload_namespaces.php' => $header('autoload_namespaces.php')."return array(\n);\n",
            'vendor/composer/autoload_static.php' => <<<PHP
<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInit{$hash}
{
    public static \$prefixLengthsPsr4 = array (
{$prefixLengthEntries}    );

    public static \$prefixDirsPsr4 = array (
{$prefixDirs}    );

    public static \$classMap = array (
{$staticClassmapEntries}    );

    public static function getInitializer(ClassLoader \$loader)
    {
        return \Closure::bind(function () use (\$loader) {
            \$loader->prefixLengthsPsr4 = ComposerStaticInit{$hash}::\$prefixLengthsPsr4;
            \$loader->prefixDirsPsr4 = ComposerStaticInit{$hash}::\$prefixDirsPsr4;
            \$loader->classMap = ComposerStaticInit{$hash}::\$classMap;

        }, null, ClassLoader::class);
    }
}

PHP,
            'vendor/composer/autoload_real.php' => <<<PHP
<?php

// autoload_real.php @generated by Composer

class ComposerAutoloaderInit{$hash}
{
    private static \$loader;

    public static function getLoader()
    {
        if (null !== self::\$loader) {
            return self::\$loader;
        }

        self::\$loader = \$loader = new \Composer\Autoload\ClassLoader(\dirname(__DIR__));

        require __DIR__ . '/autoload_static.php';
        call_user_func(\Composer\Autoload\ComposerStaticInit{$hash}::getInitializer(\$loader));

{$authoritative}        \$loader->register(true);

        return \$loader;
    }
}

PHP,
        ];
    }
}
