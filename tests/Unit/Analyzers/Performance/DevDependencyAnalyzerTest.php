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
}
