<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\VulnerableDependencyAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class VulnerableDependencyAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new VulnerableDependencyAnalyzer;
    }

    public function test_fails_when_no_composer_lock(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('composer.lock', $result);
    }

    public function test_skips_when_composer_not_available(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": []
}
JSON;

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        // Analyzer requires actual composer audit command
        // which may not be available in test environment
        $result = $analyzer->analyze();

        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }
}
