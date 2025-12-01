<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use Mockery;
use Mockery\MockInterface;
use RuntimeException;
use ShieldCI\Analyzers\Security\VulnerableDependencyAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Support\SecurityAdvisories\AdvisoryAnalyzerInterface;
use ShieldCI\Support\SecurityAdvisories\AdvisoryFetcherInterface;
use ShieldCI\Support\SecurityAdvisories\ComposerDependencyReader;
use ShieldCI\Tests\AnalyzerTestCase;
use function assert;

class VulnerableDependencyAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param (AdvisoryFetcherInterface&MockInterface)|null $fetcher
     * @param (AdvisoryAnalyzerInterface&MockInterface)|null $analyzer
     * @param (ComposerDependencyReader&MockInterface)|null $dependencyReader
     */
    protected function createAnalyzer(
        ?AdvisoryFetcherInterface $fetcher = null,
        ?AdvisoryAnalyzerInterface $analyzer = null,
        ?ComposerDependencyReader $dependencyReader = null,
    ): AnalyzerInterface {
        /** @var AdvisoryFetcherInterface&MockInterface $fetcher */
        $fetcher ??= Mockery::mock(AdvisoryFetcherInterface::class);
        /** @var AdvisoryAnalyzerInterface&MockInterface $analyzer */
        $analyzer ??= Mockery::mock(AdvisoryAnalyzerInterface::class);
        /** @var ComposerDependencyReader&MockInterface $dependencyReader */
        $dependencyReader ??= Mockery::mock(ComposerDependencyReader::class);

        assert($fetcher instanceof AdvisoryFetcherInterface);
        assert($analyzer instanceof AdvisoryAnalyzerInterface);
        assert($dependencyReader instanceof ComposerDependencyReader);

        return new VulnerableDependencyAnalyzer($fetcher, $analyzer, $dependencyReader);
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

    public function test_reports_vulnerabilities_from_scanner(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [
        {
            "name": "vendor/package",
            "version": "1.0.0",
            "time": "2024-01-01"
        }
    ]
}
JSON;

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
        ]);

        $dependencies = ['vendor/package' => ['version' => '1.0.0', 'time' => null]];

        /** @var AdvisoryFetcherInterface&MockInterface $fetcher */
        $fetcher = Mockery::mock(AdvisoryFetcherInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $fetcher->shouldReceive('fetch')
            ->with($dependencies)
            ->andReturn(['vendor/package' => []]);

        /** @var ComposerDependencyReader&MockInterface $dependencyReader */
        $dependencyReader = Mockery::mock(ComposerDependencyReader::class);
        $dependencyReader->shouldReceive('read')
            ->andReturn($dependencies);

        $analysisOutput = [
            'vendor/package' => [
                'version' => '1.0.0',
                'advisories' => [
                    [
                        'title' => 'Remote code execution',
                        'cve' => 'CVE-2024-1234',
                        'link' => 'https://example.com/advisory',
                        'affected_versions' => ['<=1.0.0'],
                    ],
                ],
            ],
        ];

        /** @var AdvisoryAnalyzerInterface&MockInterface $advisoryAnalyzer */
        $advisoryAnalyzer = Mockery::mock(AdvisoryAnalyzerInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $advisoryAnalyzer->shouldReceive('analyze')
            ->andReturn($analysisOutput);

        $analyzer = $this->createAnalyzer($fetcher, $advisoryAnalyzer, $dependencyReader);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('vendor/package', $result);
        $issues = $result->getIssues();
        $this->assertEquals('CVE-2024-1234', $issues[0]->metadata['cve'] ?? null);
    }

    public function test_passes_when_no_vulnerabilities_detected(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": []
}
JSON;

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
        ]);

        /** @var AdvisoryFetcherInterface&MockInterface $fetcher */
        $fetcher = Mockery::mock(AdvisoryFetcherInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $fetcher->shouldReceive('fetch')->never();

        /** @var ComposerDependencyReader&MockInterface $dependencyReader */
        $dependencyReader = Mockery::mock(ComposerDependencyReader::class);
        $dependencyReader->shouldReceive('read')->andReturn([]);

        /** @var AdvisoryAnalyzerInterface&MockInterface $advisoryAnalyzer */
        $advisoryAnalyzer = Mockery::mock(AdvisoryAnalyzerInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $advisoryAnalyzer->shouldReceive('analyze')->andReturn([]);

        $analyzer = $this->createAnalyzer($fetcher, $advisoryAnalyzer, $dependencyReader);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_returns_error_when_fetcher_fails(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": []
}
JSON;

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
        ]);

        $dependencies = ['vendor/package' => ['version' => '1.0.0', 'time' => null]];

        /** @var AdvisoryFetcherInterface&MockInterface $fetcher */
        $fetcher = Mockery::mock(AdvisoryFetcherInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $fetcher->shouldReceive('fetch')
            ->with($dependencies)
            ->andThrow(new RuntimeException('network error'));

        /** @var ComposerDependencyReader&MockInterface $dependencyReader */
        $dependencyReader = Mockery::mock(ComposerDependencyReader::class);
        $dependencyReader->shouldReceive('read')->andReturn($dependencies);

        /** @var AdvisoryAnalyzerInterface&MockInterface $advisoryAnalyzer */
        $advisoryAnalyzer = Mockery::mock(AdvisoryAnalyzerInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $advisoryAnalyzer->shouldReceive('analyze')->never();

        $analyzer = $this->createAnalyzer($fetcher, $advisoryAnalyzer, $dependencyReader);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertError($result);
        $this->assertStringContainsString('network error', $result->getMessage());
    }

    public function test_returns_error_when_dependency_reader_fails(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": []
}
JSON;

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
        ]);

        /** @var AdvisoryFetcherInterface&\Mockery\MockInterface $fetcher */
        $fetcher = Mockery::mock(AdvisoryFetcherInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $fetcher->shouldReceive('fetch')->never();

        /** @var ComposerDependencyReader&MockInterface $dependencyReader */
        $dependencyReader = Mockery::mock(ComposerDependencyReader::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $dependencyReader->shouldReceive('read')->andThrow(new RuntimeException('invalid file'));

        /** @var AdvisoryAnalyzerInterface&MockInterface $advisoryAnalyzer */
        $advisoryAnalyzer = Mockery::mock(AdvisoryAnalyzerInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $advisoryAnalyzer->shouldReceive('analyze')->never();

        $analyzer = $this->createAnalyzer($fetcher, $advisoryAnalyzer, $dependencyReader);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertError($result);
        $this->assertStringContainsString('invalid file', $result->getMessage());
    }

    public function test_reports_abandoned_package_with_replacement(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [
        {
            "name": "legacy/package",
            "version": "1.0.0",
            "abandoned": "new/package"
        }
    ]
}
JSON;

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
        ]);

        /** @var AdvisoryFetcherInterface&\Mockery\MockInterface $fetcher */
        $fetcher = Mockery::mock(AdvisoryFetcherInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $fetcher->shouldReceive('fetch')->never();

        /** @var ComposerDependencyReader&MockInterface $dependencyReader */
        $dependencyReader = Mockery::mock(ComposerDependencyReader::class);
        $dependencyReader->shouldReceive('read')->andReturn([]);

        /** @var AdvisoryAnalyzerInterface&MockInterface $advisoryAnalyzer */
        $advisoryAnalyzer = Mockery::mock(AdvisoryAnalyzerInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $advisoryAnalyzer->shouldReceive('analyze')->andReturn([]);

        $analyzer = $this->createAnalyzer($fetcher, $advisoryAnalyzer, $dependencyReader);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('legacy/package', $result);
        $this->assertStringContainsString('new/package', $result->getIssues()[0]->recommendation);
    }

    public function test_reports_abandoned_package_without_replacement(): void
    {
        $composerLock = <<<'JSON'
{
    "packages-dev": [
        {
            "name": "legacy/dev-package",
            "version": "1.0.0",
            "abandoned": true
        }
    ]
}
JSON;

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
        ]);

        /** @var AdvisoryFetcherInterface&\Mockery\MockInterface $fetcher */
        $fetcher = Mockery::mock(AdvisoryFetcherInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $fetcher->shouldReceive('fetch')->never();

        /** @var ComposerDependencyReader&MockInterface $dependencyReader */
        $dependencyReader = Mockery::mock(ComposerDependencyReader::class);
        $dependencyReader->shouldReceive('read')->andReturn([]);

        /** @var AdvisoryAnalyzerInterface&MockInterface $advisoryAnalyzer */
        $advisoryAnalyzer = Mockery::mock(AdvisoryAnalyzerInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $advisoryAnalyzer->shouldReceive('analyze')->andReturn([]);

        $analyzer = $this->createAnalyzer($fetcher, $advisoryAnalyzer, $dependencyReader);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('legacy/dev-package', $result);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
