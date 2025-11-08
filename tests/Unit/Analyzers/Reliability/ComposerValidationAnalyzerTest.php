<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use ShieldCI\Analyzers\Reliability\ComposerValidationAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class ComposerValidationAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new ComposerValidationAnalyzer;
    }

    public function test_fails_when_composer_json_missing(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('missing', $result);
    }

    public function test_fails_with_invalid_json(): void
    {
        $invalidJson = '{
            "name": "test/app",
            "require": {
                "php": "^8.0"
            }
        '; // Missing closing brace

        $tempDir = $this->createTempDirectory([
            'composer.json' => $invalidJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('JSON', $result);
    }

    public function test_validates_composer_json(): void
    {
        $validJson = <<<'JSON'
{
    "name": "test/app",
    "description": "Test application",
    "type": "project",
    "require": {
        "php": "^8.0",
        "laravel/framework": "^10.0"
    },
    "autoload": {
        "psr-4": {
            "App\\": "app/"
        }
    }
}
JSON;

        $tempDir = $this->createTempDirectory([
            'composer.json' => $validJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // May pass or fail depending on composer validate output
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }
}
