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
     * @param  (AdvisoryFetcherInterface&MockInterface)|null  $fetcher
     * @param  (AdvisoryAnalyzerInterface&MockInterface)|null  $analyzer
     * @param  (ComposerDependencyReader&MockInterface)|null  $dependencyReader
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

    public function test_skips_when_no_composer_lock(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        // Should not run when composer.lock is missing - can't check vulnerabilities without it
        $this->assertFalse($analyzer->shouldRun());

        if (method_exists($analyzer, 'getSkipReason')) {
            $this->assertStringContainsString('composer.lock', $analyzer->getSkipReason());
        }
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
        $this->assertHasIssueContaining('legacy/dev-package', $result);
    }

    public function test_handles_multiple_vulnerabilities_for_single_package(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [
        {
            "name": "vendor/package",
            "version": "1.0.0"
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
        $fetcher->shouldReceive('fetch')->andReturn(['vendor/package' => []]);

        /** @var ComposerDependencyReader&MockInterface $dependencyReader */
        $dependencyReader = Mockery::mock(ComposerDependencyReader::class);
        $dependencyReader->shouldReceive('read')->andReturn($dependencies);

        $analysisOutput = [
            'vendor/package' => [
                'version' => '1.0.0',
                'advisories' => [
                    [
                        'title' => 'SQL Injection',
                        'cve' => 'CVE-2024-1111',
                        'link' => 'https://example.com/advisory1',
                    ],
                    [
                        'title' => 'XSS Vulnerability',
                        'cve' => 'CVE-2024-2222',
                        'link' => 'https://example.com/advisory2',
                    ],
                ],
            ],
        ];

        /** @var AdvisoryAnalyzerInterface&MockInterface $advisoryAnalyzer */
        $advisoryAnalyzer = Mockery::mock(AdvisoryAnalyzerInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $advisoryAnalyzer->shouldReceive('analyze')->andReturn($analysisOutput);

        $analyzer = $this->createAnalyzer($fetcher, $advisoryAnalyzer, $dependencyReader);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
        $this->assertEquals('CVE-2024-1111', $issues[0]->metadata['cve'] ?? null);
        $this->assertEquals('CVE-2024-2222', $issues[1]->metadata['cve'] ?? null);
    }

    public function test_handles_vulnerability_without_cve(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [
        {
            "name": "vendor/package",
            "version": "1.0.0"
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
        $fetcher->shouldReceive('fetch')->andReturn(['vendor/package' => []]);

        /** @var ComposerDependencyReader&MockInterface $dependencyReader */
        $dependencyReader = Mockery::mock(ComposerDependencyReader::class);
        $dependencyReader->shouldReceive('read')->andReturn($dependencies);

        $analysisOutput = [
            'vendor/package' => [
                'version' => '1.0.0',
                'advisories' => [
                    [
                        'title' => 'Security Issue',
                        'link' => 'https://example.com/advisory',
                        // No CVE field
                    ],
                ],
            ],
        ];

        /** @var AdvisoryAnalyzerInterface&MockInterface $advisoryAnalyzer */
        $advisoryAnalyzer = Mockery::mock(AdvisoryAnalyzerInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $advisoryAnalyzer->shouldReceive('analyze')->andReturn($analysisOutput);

        $analyzer = $this->createAnalyzer($fetcher, $advisoryAnalyzer, $dependencyReader);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertNull($issues[0]->metadata['cve'] ?? null);
        $this->assertStringContainsString('Security Issue', $issues[0]->message);
    }

    public function test_handles_vulnerability_without_link(): void
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
        $fetcher->shouldReceive('fetch')->andReturn(['vendor/package' => []]);

        /** @var ComposerDependencyReader&MockInterface $dependencyReader */
        $dependencyReader = Mockery::mock(ComposerDependencyReader::class);
        $dependencyReader->shouldReceive('read')->andReturn($dependencies);

        $analysisOutput = [
            'vendor/package' => [
                'version' => '1.0.0',
                'advisories' => [
                    [
                        'title' => 'Security Issue',
                        'cve' => 'CVE-2024-5555',
                        // No link field
                    ],
                ],
            ],
        ];

        /** @var AdvisoryAnalyzerInterface&MockInterface $advisoryAnalyzer */
        $advisoryAnalyzer = Mockery::mock(AdvisoryAnalyzerInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $advisoryAnalyzer->shouldReceive('analyze')->andReturn($analysisOutput);

        $analyzer = $this->createAnalyzer($fetcher, $advisoryAnalyzer, $dependencyReader);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertNull($issues[0]->metadata['link'] ?? null);
        $this->assertStringNotContainsString('See http', $issues[0]->recommendation);
    }

    public function test_handles_advisory_with_array_affected_versions(): void
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
        $fetcher->shouldReceive('fetch')->andReturn(['vendor/package' => []]);

        /** @var ComposerDependencyReader&MockInterface $dependencyReader */
        $dependencyReader = Mockery::mock(ComposerDependencyReader::class);
        $dependencyReader->shouldReceive('read')->andReturn($dependencies);

        $analysisOutput = [
            'vendor/package' => [
                'version' => '1.0.0',
                'advisories' => [
                    [
                        'title' => 'Security Issue',
                        'affected_versions' => ['<1.1.0', '>=2.0.0,<2.1.0'],
                    ],
                ],
            ],
        ];

        /** @var AdvisoryAnalyzerInterface&MockInterface $advisoryAnalyzer */
        $advisoryAnalyzer = Mockery::mock(AdvisoryAnalyzerInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $advisoryAnalyzer->shouldReceive('analyze')->andReturn($analysisOutput);

        $analyzer = $this->createAnalyzer($fetcher, $advisoryAnalyzer, $dependencyReader);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('Affected versions:', $issues[0]->recommendation);
        $this->assertStringContainsString('<1.1.0', $issues[0]->recommendation);
    }

    public function test_handles_advisory_with_string_affected_versions(): void
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
        $fetcher->shouldReceive('fetch')->andReturn(['vendor/package' => []]);

        /** @var ComposerDependencyReader&MockInterface $dependencyReader */
        $dependencyReader = Mockery::mock(ComposerDependencyReader::class);
        $dependencyReader->shouldReceive('read')->andReturn($dependencies);

        $analysisOutput = [
            'vendor/package' => [
                'version' => '1.0.0',
                'advisories' => [
                    [
                        'title' => 'Security Issue',
                        'affected_versions' => '<1.1.0',
                    ],
                ],
            ],
        ];

        /** @var AdvisoryAnalyzerInterface&MockInterface $advisoryAnalyzer */
        $advisoryAnalyzer = Mockery::mock(AdvisoryAnalyzerInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $advisoryAnalyzer->shouldReceive('analyze')->andReturn($analysisOutput);

        $analyzer = $this->createAnalyzer($fetcher, $advisoryAnalyzer, $dependencyReader);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('Affected versions: <1.1.0', $issues[0]->recommendation);
    }

    public function test_handles_invalid_json_in_composer_lock(): void
    {
        $composerLock = 'invalid json {';

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
        ]);

        /** @var AdvisoryFetcherInterface&MockInterface $fetcher */
        $fetcher = Mockery::mock(AdvisoryFetcherInterface::class);

        /** @var ComposerDependencyReader&MockInterface $dependencyReader */
        $dependencyReader = Mockery::mock(ComposerDependencyReader::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $dependencyReader->shouldReceive('read')->andReturn([]);

        /** @var AdvisoryAnalyzerInterface&MockInterface $advisoryAnalyzer */
        $advisoryAnalyzer = Mockery::mock(AdvisoryAnalyzerInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $advisoryAnalyzer->shouldReceive('analyze')->andReturn([]);

        $analyzer = $this->createAnalyzer($fetcher, $advisoryAnalyzer, $dependencyReader);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass (no abandoned packages can be read from invalid JSON)
        $this->assertPassed($result);
    }

    public function test_handles_both_vulnerabilities_and_abandoned_packages(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [
        {
            "name": "vendor/vulnerable",
            "version": "1.0.0"
        },
        {
            "name": "legacy/abandoned",
            "version": "2.0.0",
            "abandoned": "new/package"
        }
    ]
}
JSON;

        $tempDir = $this->createTempDirectory([
            'composer.lock' => $composerLock,
        ]);

        $dependencies = ['vendor/vulnerable' => ['version' => '1.0.0', 'time' => null]];

        /** @var AdvisoryFetcherInterface&MockInterface $fetcher */
        $fetcher = Mockery::mock(AdvisoryFetcherInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $fetcher->shouldReceive('fetch')->andReturn(['vendor/vulnerable' => []]);

        /** @var ComposerDependencyReader&MockInterface $dependencyReader */
        $dependencyReader = Mockery::mock(ComposerDependencyReader::class);
        $dependencyReader->shouldReceive('read')->andReturn($dependencies);

        $analysisOutput = [
            'vendor/vulnerable' => [
                'version' => '1.0.0',
                'advisories' => [
                    [
                        'title' => 'Security Issue',
                        'cve' => 'CVE-2024-9999',
                    ],
                ],
            ],
        ];

        /** @var AdvisoryAnalyzerInterface&MockInterface $advisoryAnalyzer */
        $advisoryAnalyzer = Mockery::mock(AdvisoryAnalyzerInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $advisoryAnalyzer->shouldReceive('analyze')->andReturn($analysisOutput);

        $analyzer = $this->createAnalyzer($fetcher, $advisoryAnalyzer, $dependencyReader);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);

        // One vulnerability, one abandoned package
        $hasVulnerability = false;
        $hasAbandoned = false;

        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'vulnerability')) {
                $hasVulnerability = true;
            }
            if (str_contains($issue->message, 'abandoned')) {
                $hasAbandoned = true;
            }
        }

        $this->assertTrue($hasVulnerability);
        $this->assertTrue($hasAbandoned);
    }

    public function test_severity_is_critical_for_vulnerabilities(): void
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
        $fetcher->shouldReceive('fetch')->andReturn(['vendor/package' => []]);

        /** @var ComposerDependencyReader&MockInterface $dependencyReader */
        $dependencyReader = Mockery::mock(ComposerDependencyReader::class);
        $dependencyReader->shouldReceive('read')->andReturn($dependencies);

        $analysisOutput = [
            'vendor/package' => [
                'version' => '1.0.0',
                'advisories' => [
                    ['title' => 'Security Issue'],
                ],
            ],
        ];

        /** @var AdvisoryAnalyzerInterface&MockInterface $advisoryAnalyzer */
        $advisoryAnalyzer = Mockery::mock(AdvisoryAnalyzerInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $advisoryAnalyzer->shouldReceive('analyze')->andReturn($analysisOutput);

        $analyzer = $this->createAnalyzer($fetcher, $advisoryAnalyzer, $dependencyReader);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $issues[0]->severity);
    }

    public function test_severity_is_medium_for_abandoned_packages(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [
        {
            "name": "legacy/package",
            "version": "1.0.0",
            "abandoned": true
        }
    ]
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

        $issues = $result->getIssues();
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $issues[0]->severity);
    }

    public function test_metadata_structure(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertEquals('vulnerable-dependencies', $metadata->id);
        $this->assertEquals('Vulnerable Dependencies Analyzer', $metadata->name);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Category::Security, $metadata->category);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $metadata->severity);
        $this->assertContains('vulnerabilities', $metadata->tags);
        $this->assertContains('cve', $metadata->tags);
    }

    public function test_recommendation_format_with_all_fields(): void
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
        $fetcher->shouldReceive('fetch')->andReturn(['vendor/package' => []]);

        /** @var ComposerDependencyReader&MockInterface $dependencyReader */
        $dependencyReader = Mockery::mock(ComposerDependencyReader::class);
        $dependencyReader->shouldReceive('read')->andReturn($dependencies);

        $analysisOutput = [
            'vendor/package' => [
                'version' => '1.0.0',
                'advisories' => [
                    [
                        'title' => 'Security Issue',
                        'link' => 'https://example.com/advisory',
                        'affected_versions' => '<1.1.0',
                    ],
                ],
            ],
        ];

        /** @var AdvisoryAnalyzerInterface&MockInterface $advisoryAnalyzer */
        $advisoryAnalyzer = Mockery::mock(AdvisoryAnalyzerInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $advisoryAnalyzer->shouldReceive('analyze')->andReturn($analysisOutput);

        $analyzer = $this->createAnalyzer($fetcher, $advisoryAnalyzer, $dependencyReader);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $recommendation = $issues[0]->recommendation;

        $this->assertStringContainsString('Update "vendor/package"', $recommendation);
        $this->assertStringContainsString('https://example.com/advisory', $recommendation);
        $this->assertStringContainsString('Affected versions: <1.1.0', $recommendation);
    }

    public function test_abandoned_package_with_empty_string_replacement(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [
        {
            "name": "legacy/package",
            "version": "1.0.0",
            "abandoned": ""
        }
    ]
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

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('Find an alternative', $issues[0]->recommendation);
    }

    public function test_handles_packages_and_packages_dev_merged(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [
        {
            "name": "regular/package",
            "version": "1.0.0",
            "abandoned": true
        }
    ],
    "packages-dev": [
        {
            "name": "dev/package",
            "version": "2.0.0",
            "abandoned": "new/dev-package"
        }
    ]
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

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
    }

    public function test_skips_malformed_package_in_abandoned_check(): void
    {
        $composerLock = <<<'JSON'
{
    "packages": [
        {
            "version": "1.0.0",
            "abandoned": true
        }
    ]
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

        $this->assertWarning($result);
        $issues = $result->getIssues();
        // Should create issue but with "Unknown" package name
        $this->assertStringContainsString('Unknown', $issues[0]->message);
    }

    public function test_skips_advisory_without_title(): void
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
        $fetcher->shouldReceive('fetch')->andReturn(['vendor/package' => []]);

        /** @var ComposerDependencyReader&MockInterface $dependencyReader */
        $dependencyReader = Mockery::mock(ComposerDependencyReader::class);
        $dependencyReader->shouldReceive('read')->andReturn($dependencies);

        $analysisOutput = [
            'vendor/package' => [
                'version' => '1.0.0',
                'advisories' => [
                    [
                        // No title field - should be skipped
                        'cve' => 'CVE-2024-9999',
                    ],
                ],
            ],
        ];

        /** @var AdvisoryAnalyzerInterface&MockInterface $advisoryAnalyzer */
        $advisoryAnalyzer = Mockery::mock(AdvisoryAnalyzerInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $advisoryAnalyzer->shouldReceive('analyze')->andReturn($analysisOutput);

        $analyzer = $this->createAnalyzer($fetcher, $advisoryAnalyzer, $dependencyReader);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass because advisory without title is skipped
        $this->assertPassed($result);
    }

    public function test_skips_empty_advisory_array(): void
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
        $fetcher->shouldReceive('fetch')->andReturn(['vendor/package' => []]);

        /** @var ComposerDependencyReader&MockInterface $dependencyReader */
        $dependencyReader = Mockery::mock(ComposerDependencyReader::class);
        $dependencyReader->shouldReceive('read')->andReturn($dependencies);

        $analysisOutput = [
            'vendor/package' => [
                'version' => '1.0.0',
                'advisories' => [
                    [], // Empty advisory array - should be skipped
                ],
            ],
        ];

        /** @var AdvisoryAnalyzerInterface&MockInterface $advisoryAnalyzer */
        $advisoryAnalyzer = Mockery::mock(AdvisoryAnalyzerInterface::class);
        /** @phpstan-ignore-next-line Mockery fluent interface */
        $advisoryAnalyzer->shouldReceive('analyze')->andReturn($analysisOutput);

        $analyzer = $this->createAnalyzer($fetcher, $advisoryAnalyzer, $dependencyReader);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Should pass because empty advisory is skipped
        $this->assertPassed($result);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
