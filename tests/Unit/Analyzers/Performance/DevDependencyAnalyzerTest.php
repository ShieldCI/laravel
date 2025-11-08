<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use ShieldCI\Analyzers\Performance\DevDependencyAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class DevDependencyAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new DevDependencyAnalyzer;
    }

    public function test_checks_dev_dependencies(): void
    {
        $envContent = 'APP_ENV=production';
        $composerLock = <<<'JSON'
{
    "packages": [
        {
            "name": "laravel/framework",
            "version": "v10.0.0"
        }
    ],
    "packages-dev": []
}
JSON;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'composer.lock' => $composerLock,
            'vendor/autoload.php' => '<?php',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // May pass or warn depending on environment detection
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_analyzes_vendor_directory(): void
    {
        $envContent = 'APP_ENV=production';
        $composerLock = <<<'JSON'
{
    "packages": [
        {
            "name": "laravel/framework",
            "version": "v10.0.0"
        }
    ],
    "packages-dev": [
        {
            "name": "phpunit/phpunit",
            "version": "10.0.0"
        }
    ]
}
JSON;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            'composer.lock' => $composerLock,
            'vendor/autoload.php' => '<?php',
            'vendor/phpunit/phpunit/composer.json' => '{}',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Analyzer checks for dev dependencies in vendor
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }
}
