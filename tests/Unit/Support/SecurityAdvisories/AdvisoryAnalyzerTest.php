<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support\SecurityAdvisories;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Support\SecurityAdvisories\AdvisoryAnalyzer;
use ShieldCI\Support\SecurityAdvisories\VersionConstraintMatcher;
use ShieldCI\Tests\TestCase;

class AdvisoryAnalyzerTest extends TestCase
{
    private AdvisoryAnalyzer $analyzer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->analyzer = new AdvisoryAnalyzer(new VersionConstraintMatcher);
    }

    /** @test */
    #[Test]
    public function it_finds_vulnerable_dependencies(): void
    {
        $dependencies = [
            'guzzlehttp/guzzle' => ['version' => '7.4.0'],
        ];

        $advisories = [
            'guzzlehttp/guzzle' => [
                [
                    'title' => 'Security vulnerability in Guzzle',
                    'cve' => 'CVE-2022-29248',
                    'link' => 'https://example.com/advisory',
                    'affected_versions' => ['^7.0', '<7.4.5'],
                ],
            ],
        ];

        $results = $this->analyzer->analyze($dependencies, $advisories);

        $this->assertArrayHasKey('guzzlehttp/guzzle', $results);
        $this->assertEquals('7.4.0', $results['guzzlehttp/guzzle']['version']);
        $this->assertCount(1, $results['guzzlehttp/guzzle']['advisories']);
        $this->assertEquals('Security vulnerability in Guzzle', $results['guzzlehttp/guzzle']['advisories'][0]['title']);
    }

    /** @test */
    #[Test]
    public function it_ignores_non_vulnerable_dependencies(): void
    {
        $dependencies = [
            'guzzlehttp/guzzle' => ['version' => '7.5.0'],
        ];

        $advisories = [
            'guzzlehttp/guzzle' => [
                [
                    'title' => 'Security vulnerability',
                    'affected_versions' => ['<7.4.5'],
                ],
            ],
        ];

        $results = $this->analyzer->analyze($dependencies, $advisories);

        $this->assertEmpty($results);
    }

    /** @test */
    #[Test]
    public function it_handles_packages_without_advisories(): void
    {
        $dependencies = [
            'laravel/framework' => ['version' => '10.0.0'],
            'guzzlehttp/guzzle' => ['version' => '7.5.0'],
        ];

        $advisories = [
            // No advisories for these packages
        ];

        $results = $this->analyzer->analyze($dependencies, $advisories);

        $this->assertEmpty($results);
    }

    /** @test */
    #[Test]
    public function it_handles_multiple_advisories_per_package(): void
    {
        $dependencies = [
            'vulnerable/package' => ['version' => '1.0.0'],
        ];

        $advisories = [
            'vulnerable/package' => [
                [
                    'title' => 'First vulnerability',
                    'cve' => 'CVE-2024-0001',
                    'affected_versions' => ['^1.0'],
                ],
                [
                    'title' => 'Second vulnerability',
                    'cve' => 'CVE-2024-0002',
                    'affected_versions' => ['<1.5.0'],
                ],
            ],
        ];

        $results = $this->analyzer->analyze($dependencies, $advisories);

        $this->assertCount(2, $results['vulnerable/package']['advisories']);
    }

    /** @test */
    #[Test]
    public function it_handles_affected_versions_key_format(): void
    {
        $dependencies = [
            'test/package' => ['version' => '1.0.0'],
        ];

        $advisories = [
            'test/package' => [
                [
                    'title' => 'Vulnerability',
                    'affectedVersions' => ['^1.0'],  // camelCase format
                ],
            ],
        ];

        $results = $this->analyzer->analyze($dependencies, $advisories);

        $this->assertArrayHasKey('test/package', $results);
    }

    /** @test */
    #[Test]
    public function it_handles_affected_versions_as_string(): void
    {
        $dependencies = [
            'test/package' => ['version' => '1.0.0'],
        ];

        $advisories = [
            'test/package' => [
                [
                    'title' => 'Vulnerability',
                    'affected_versions' => '^1.0',  // String instead of array
                ],
            ],
        ];

        $results = $this->analyzer->analyze($dependencies, $advisories);

        $this->assertArrayHasKey('test/package', $results);
    }

    /** @test */
    #[Test]
    public function it_handles_missing_advisory_fields(): void
    {
        $dependencies = [
            'test/package' => ['version' => '1.0.0'],
        ];

        $advisories = [
            'test/package' => [
                [
                    'affected_versions' => ['^1.0'],
                    // Missing title, cve, link
                ],
            ],
        ];

        $results = $this->analyzer->analyze($dependencies, $advisories);

        $this->assertArrayHasKey('test/package', $results);
        $this->assertEquals('Known vulnerability', $results['test/package']['advisories'][0]['title']);
        $this->assertNull($results['test/package']['advisories'][0]['cve']);
        $this->assertNull($results['test/package']['advisories'][0]['link']);
    }

    /** @test */
    #[Test]
    public function it_skips_non_array_advisories(): void
    {
        $dependencies = [
            'test/package' => ['version' => '1.0.0'],
        ];

        $advisories = [
            'test/package' => [
                'not-an-array',
                null,
                [
                    'title' => 'Valid advisory',
                    'affected_versions' => ['^1.0'],
                ],
            ],
        ];

        $results = $this->analyzer->analyze($dependencies, $advisories);

        $this->assertCount(1, $results['test/package']['advisories']);
    }

    /** @test */
    #[Test]
    public function it_skips_dependencies_with_non_string_version(): void
    {
        $dependencies = [
            'test/package' => ['version' => ['invalid']],
            'valid/package' => ['version' => '1.0.0'],
        ];

        $advisories = [
            'test/package' => [
                ['title' => 'Advisory', 'affected_versions' => ['*']],
            ],
            'valid/package' => [
                ['title' => 'Advisory', 'affected_versions' => ['^1.0']],
            ],
        ];

        $results = $this->analyzer->analyze($dependencies, $advisories);

        $this->assertCount(1, $results);
        $this->assertArrayHasKey('valid/package', $results);
    }

    /** @test */
    #[Test]
    public function it_handles_non_array_advisories_list(): void
    {
        $dependencies = [
            'test/package' => ['version' => '1.0.0'],
        ];

        $advisories = [
            'test/package' => 'not-an-array',
        ];

        $results = $this->analyzer->analyze($dependencies, $advisories);

        $this->assertEmpty($results);
    }

    /** @test */
    #[Test]
    public function it_filters_non_string_affected_versions(): void
    {
        $dependencies = [
            'test/package' => ['version' => '1.0.0'],
        ];

        $advisories = [
            'test/package' => [
                [
                    'title' => 'Advisory',
                    'affected_versions' => ['^1.0', null, 123, ['array'], '<2.0'],
                ],
            ],
        ];

        $results = $this->analyzer->analyze($dependencies, $advisories);

        // Should still match because ^1.0 and <2.0 are valid string constraints
        $this->assertArrayHasKey('test/package', $results);
        // The affected_versions in result should only have string values
        $affectedVersions = $results['test/package']['advisories'][0]['affected_versions'];
        $this->assertEquals(['^1.0', '<2.0'], $affectedVersions);
    }

    /** @test */
    #[Test]
    public function it_includes_advisory_link_and_cve(): void
    {
        $dependencies = [
            'test/package' => ['version' => '1.0.0'],
        ];

        $advisories = [
            'test/package' => [
                [
                    'title' => 'Critical vulnerability',
                    'cve' => 'CVE-2024-12345',
                    'link' => 'https://nvd.nist.gov/vuln/detail/CVE-2024-12345',
                    'affected_versions' => ['^1.0'],
                ],
            ],
        ];

        $results = $this->analyzer->analyze($dependencies, $advisories);

        $advisory = $results['test/package']['advisories'][0];
        $this->assertEquals('CVE-2024-12345', $advisory['cve']);
        $this->assertEquals('https://nvd.nist.gov/vuln/detail/CVE-2024-12345', $advisory['link']);
    }

    /** @test */
    #[Test]
    public function it_handles_empty_dependencies(): void
    {
        $results = $this->analyzer->analyze([], [
            'test/package' => [
                ['title' => 'Advisory', 'affected_versions' => ['*']],
            ],
        ]);

        $this->assertEmpty($results);
    }

    /** @test */
    #[Test]
    public function it_handles_empty_advisories(): void
    {
        $results = $this->analyzer->analyze([
            'test/package' => ['version' => '1.0.0'],
        ], []);

        $this->assertEmpty($results);
    }

    /** @test */
    #[Test]
    public function it_reports_advisory_with_unusable_affected_versions_fail_open(): void
    {
        $dependencies = [
            'test/package' => ['version' => '1.0.0'],
        ];

        $advisories = [
            'test/package' => [
                [
                    'title' => 'Advisory with numeric affected_versions',
                    'affected_versions' => 42,
                ],
            ],
        ];

        $results = $this->analyzer->analyze($dependencies, $advisories);

        // Fail open: when affected_versions is neither array nor string it normalizes
        // to an empty range. Rather than silently hide an OSV-confirmed advisory, we
        // still report it (the matcher can only drop when it has real constraints).
        $this->assertArrayHasKey('test/package', $results);
        $this->assertSame([], $results['test/package']['advisories'][0]['affected_versions']);
    }

    /** @test */
    #[Test]
    public function it_reports_advisory_with_empty_affected_versions_fail_open(): void
    {
        $dependencies = [
            'test/package' => ['version' => '1.0.0'],
        ];

        $advisories = [
            'test/package' => [
                [
                    'title' => 'Advisory whose range could not be resolved',
                    'affected_versions' => [],
                ],
            ],
        ];

        $results = $this->analyzer->analyze($dependencies, $advisories);

        $this->assertArrayHasKey('test/package', $results);
        $this->assertCount(1, $results['test/package']['advisories']);
    }

    /** @test */
    #[Test]
    public function it_drops_advisory_when_version_outside_real_range(): void
    {
        $dependencies = [
            'guzzlehttp/guzzle' => ['version' => '7.15.2'],
        ];

        $advisories = [
            'guzzlehttp/guzzle' => [
                [
                    'title' => 'Fixed before installed version',
                    'affected_versions' => ['<7.15.1'],
                ],
            ],
        ];

        $results = $this->analyzer->analyze($dependencies, $advisories);

        $this->assertEmpty($results);
    }

    /** @test */
    #[Test]
    public function it_reports_advisory_when_version_inside_compound_range(): void
    {
        $dependencies = [
            'guzzlehttp/guzzle' => ['version' => '7.15.0'],
        ];

        $advisories = [
            'guzzlehttp/guzzle' => [
                [
                    'title' => 'Vulnerable up to the fix',
                    'affected_versions' => ['>=7.0.0,<7.15.1'],
                ],
            ],
        ];

        $results = $this->analyzer->analyze($dependencies, $advisories);

        $this->assertArrayHasKey('guzzlehttp/guzzle', $results);
        $this->assertCount(1, $results['guzzlehttp/guzzle']['advisories']);
    }
}
