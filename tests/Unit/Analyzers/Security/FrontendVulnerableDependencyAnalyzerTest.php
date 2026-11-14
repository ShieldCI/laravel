<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\DataProvider;
use ShieldCI\Analyzers\Security\FrontendVulnerableDependencyAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\Tests\AnalyzerTestCase;

class FrontendVulnerableDependencyAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $config
     */
    protected function createAnalyzer(array $config = []): AnalyzerInterface
    {
        // Build security config with defaults
        $securityConfig = [
            'enabled' => true,
            'frontend-vulnerable-dependencies' => [
                'ignored_packages' => $config['ignored_packages'] ?? [],
                'ignored_advisories' => $config['ignored_advisories'] ?? [],
            ],
        ];

        $configRepo = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'security' => $securityConfig,
                ],
            ],
        ]);

        return new FrontendVulnerableDependencyAnalyzer($configRepo);
    }

    // ==================== Basic Functionality Tests ====================

    public function test_skips_when_no_package_json_exists(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => '{"require": {}}',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
    }

    public function test_should_run_returns_false_when_no_package_json(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => '{"require": {}}',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertFalse($analyzer->shouldRun());
    }

    public function test_should_run_returns_true_when_package_json_exists(): void
    {
        $tempDir = $this->createTempDirectory([
            'package.json' => '{"name": "test", "dependencies": {"vue": "^3.0.0"}}',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_should_run_returns_false_when_package_json_has_no_deps(): void
    {
        $packageJson = json_encode([
            'private' => true,
            'scripts' => [],
            'devDependencies' => [],
        ]);

        $tempDir = $this->createTempDirectory([
            'package.json' => $packageJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertFalse($analyzer->shouldRun());
    }

    public function test_skips_when_package_json_has_no_deps(): void
    {
        $packageJson = json_encode([
            'private' => true,
            'scripts' => [],
            'devDependencies' => [],
        ]);

        $tempDir = $this->createTempDirectory([
            'package.json' => $packageJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertSkipped($result);
    }

    public function test_get_skip_reason_returns_correct_message(): void
    {
        $analyzer = $this->createAnalyzer();

        $reason = $analyzer->getSkipReason();

        $this->assertStringContainsString('No package.json found', $reason);
        $this->assertStringContainsString('no dependencies declared', $reason);
    }

    public function test_fails_when_package_json_exists_without_lock_file(): void
    {
        $packageJson = json_encode([
            'name' => 'test-app',
            'dependencies' => [
                'vue' => '^3.0.0',
            ],
        ]);

        $tempDir = $this->createTempDirectory([
            'package.json' => $packageJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Medium severity results in Warning status
        $this->assertWarning($result);
        $this->assertHasIssueContaining('No package-lock.json or yarn.lock found', $result);
    }

    public function test_missing_lock_file_has_medium_severity(): void
    {
        $packageJson = json_encode([
            'name' => 'test-app',
            'dependencies' => ['vue' => '^3.0.0'],
        ]);

        $tempDir = $this->createTempDirectory([
            'package.json' => $packageJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Medium severity results in Warning status
        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(Severity::Medium, $issues[0]->severity);
    }

    public function test_passes_with_package_lock_and_no_vulnerabilities(): void
    {
        $result = $this->analyzeWithFakeTool('npm', $this->npmAuditReport(), projectFiles: [
            'package.json' => $this->packageJson(['example-widget' => '^1.0.0']),
            'package-lock.json' => $this->npmLock(['example-widget'], 2),
        ]);

        $this->assertPassed($result);
        $this->assertSame('No vulnerable frontend dependencies detected', $result->getMessage());
    }

    public function test_passes_with_yarn_lock_and_no_vulnerabilities(): void
    {
        $summary = '{"type":"auditSummary","data":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":0,"critical":0},"dependencies":1}}'."\n";

        $result = $this->analyzeWithFakeTool('yarn', $summary, projectFiles: [
            'package.json' => $this->packageJson(['example-widget' => '^1.0.0']),
            'yarn.lock' => $this->yarnLock(['example-widget@^1.0.0']),
        ]);

        $this->assertPassed($result);
        $this->assertSame('No vulnerable frontend dependencies detected', $result->getMessage());
    }

    public function test_prefers_package_lock_over_yarn_lock(): void
    {
        // Only npm is on PATH: had the analyzer chosen yarn it would warn that yarn is missing.
        $result = $this->analyzeWithFakeTool('npm', $this->npmAuditReport(), projectFiles: [
            'package.json' => $this->packageJson(['example-widget' => '^1.0.0']),
            'package-lock.json' => $this->npmLock(['example-widget']),
            'yarn.lock' => $this->yarnLock(['example-widget@^1.0.0']),
        ]);

        $this->assertPassed($result);
    }

    public function test_warns_when_package_lock_has_no_packages(): void
    {
        $result = $this->analyzeWithFakeTool('npm', $this->npmAuditReport(), projectFiles: [
            'package.json' => $this->packageJson(['example-widget' => '^1.0.0']),
            'package-lock.json' => (string) json_encode(['name' => 'example-app', 'lockfileVersion' => 2, 'packages' => []]),
        ]);

        $this->assertWarning($result);
        $this->assertIssueCount(0, $result);
        $this->assertStringContainsString('package-lock.json is out of date', $result->getMessage());
    }

    // ==================== Configuration Tests ====================

    public function test_accepts_config_repository_dependency(): void
    {
        // Verify that analyzer can be created with custom config
        $customConfig = [
            'ignored_packages' => ['test-package'],
            'ignored_advisories' => ['GHSA-1234-5678-9012'],
        ];

        $analyzer = $this->createAnalyzer($customConfig);

        // Verify analyzer was created successfully
        $this->assertInstanceOf(FrontendVulnerableDependencyAnalyzer::class, $analyzer);
    }

    public function test_respects_ignored_packages_configuration(): void
    {
        $analyzer = $this->createAnalyzer([
            'ignored_packages' => ['vulnerable-package'],
            'ignored_advisories' => [],
        ]);

        $report = $this->npmAuditReport([
            'vulnerable-package' => $this->npmVulnerability('vulnerable-package', 'high', 'Prototype pollution in vulnerable-package'),
        ]);

        $result = $this->analyzeWithFakeTool('npm', $report, 1, analyzer: $analyzer, projectFiles: [
            'package.json' => $this->packageJson(['vulnerable-package' => '1.0.0']),
            'package-lock.json' => $this->npmLock(['vulnerable-package']),
        ]);

        // The only advisory is on an ignored package, so nothing is reported.
        $this->assertPassed($result);

        $property = (new \ReflectionClass($analyzer))->getProperty('ignoredPackages');
        $property->setAccessible(true);
        $this->assertContains('vulnerable-package', $property->getValue($analyzer));
    }

    public function test_respects_ignored_advisories_configuration(): void
    {
        $analyzer = $this->createAnalyzer([
            'ignored_packages' => [],
            'ignored_advisories' => ['GHSA-1234-5678-9012', 'CVE-2023-12345'],
        ]);

        $result = $this->analyzeWithFakeTool('npm', $this->npmAuditReport(), analyzer: $analyzer);

        $this->assertPassed($result);

        $property = (new \ReflectionClass($analyzer))->getProperty('ignoredAdvisories');
        $property->setAccessible(true);
        $ignoredAdvisories = $property->getValue($analyzer);

        $this->assertIsArray($ignoredAdvisories);
        $this->assertContains('GHSA-1234-5678-9012', $ignoredAdvisories);
        $this->assertContains('CVE-2023-12345', $ignoredAdvisories);
    }

    // ==================== Severity Mapping Tests ====================

    public function test_determines_critical_severity_from_summary(): void
    {
        $analyzer = $this->createAnalyzer();

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('determineSeverityFromSummary');
        $method->setAccessible(true);

        $vulnerabilities = [
            'critical' => 2,
            'high' => 5,
            'moderate' => 10,
            'low' => 3,
        ];

        $severity = $method->invoke($analyzer, $vulnerabilities);

        $this->assertEquals(Severity::Critical, $severity);
    }

    public function test_determines_high_severity_from_summary(): void
    {
        $analyzer = $this->createAnalyzer();

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('determineSeverityFromSummary');
        $method->setAccessible(true);

        $vulnerabilities = [
            'critical' => 0,
            'high' => 3,
            'moderate' => 5,
            'low' => 2,
        ];

        $severity = $method->invoke($analyzer, $vulnerabilities);

        $this->assertEquals(Severity::High, $severity);
    }

    public function test_determines_medium_severity_from_summary(): void
    {
        $analyzer = $this->createAnalyzer();

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('determineSeverityFromSummary');
        $method->setAccessible(true);

        $vulnerabilities = [
            'critical' => 0,
            'high' => 0,
            'moderate' => 8,
            'low' => 1,
        ];

        $severity = $method->invoke($analyzer, $vulnerabilities);

        $this->assertEquals(Severity::Medium, $severity);
    }

    public function test_determines_low_severity_from_summary(): void
    {
        $analyzer = $this->createAnalyzer();

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('determineSeverityFromSummary');
        $method->setAccessible(true);

        $vulnerabilities = [
            'critical' => 0,
            'high' => 0,
            'moderate' => 0,
            'low' => 5,
        ];

        $severity = $method->invoke($analyzer, $vulnerabilities);

        $this->assertEquals(Severity::Low, $severity);
    }

    // ==================== Metadata Tests ====================

    public function test_issue_metadata_includes_package_and_severity(): void
    {
        $report = $this->npmAuditReport([
            'example-widget' => $this->npmVulnerability('example-widget', 'high', 'Command injection in example-widget', 9200),
        ]);

        $result = $this->analyzeWithFakeTool('npm', $report, 1);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);

        $metadata = $result->getIssues()[0]->metadata;
        $this->assertSame('example-widget', $metadata['package']);
        $this->assertSame('high', $metadata['severity']);
        $this->assertSame('vulnerability', $metadata['issue_type']);
        $this->assertSame('https://github.com/advisories/GHSA-xxxx-9200', $metadata['advisory_url']);
    }

    public function test_yarn_summary_with_breakdown_creates_summary_issue(): void
    {
        $analyzer = $this->createAnalyzer();

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('parseYarnAuditResults');
        $method->setAccessible(true);

        $issues = [];

        $results = [
            'summary' => [
                'vulnerabilities' => [
                    'low' => 2,
                    'moderate' => 1,
                    'high' => 0,
                    'critical' => 0,
                ],
            ],
        ];

        $method->invokeArgs($analyzer, [$results, &$issues, 'yarn.lock']);

        $this->assertCount(1, $issues);

        $issue = reset($issues);
        $this->assertNotFalse($issue);
        $this->assertEquals(Severity::Medium, $issue->severity);
        $this->assertEquals('summary', $issue->metadata['issue_type']);
    }

    public function test_yarn_summary_with_info_only_maps_to_low_severity(): void
    {
        $analyzer = $this->createAnalyzer();

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('parseYarnAuditResults');
        $method->setAccessible(true);

        $issues = [];

        $results = [
            'summary' => [
                'vulnerabilities' => [
                    'info' => 3,
                ],
            ],
        ];

        $method->invokeArgs($analyzer, [$results, &$issues, 'yarn.lock']);

        $this->assertCount(1, $issues);

        $issue = reset($issues);
        $this->assertNotFalse($issue);
        $this->assertEquals(Severity::Low, $issue->severity);
    }

    public function test_yarn_numeric_summary_creates_high_severity_issue(): void
    {
        $analyzer = $this->createAnalyzer();

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('parseYarnAuditResults');
        $method->setAccessible(true);

        $issues = [];

        $results = [
            'summary' => [
                'vulnerabilities' => 4,
            ],
        ];

        $method->invokeArgs($analyzer, [$results, &$issues, 'yarn.lock']);

        $this->assertCount(1, $issues);

        $issue = reset($issues);
        $this->assertNotFalse($issue);
        $this->assertEquals(Severity::High, $issue->severity);
    }

    public function test_yarn_summary_not_created_when_advisories_exist(): void
    {
        $analyzer = $this->createAnalyzer();

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('parseYarnAuditResults');
        $method->setAccessible(true);

        $issues = [];

        $results = [
            'advisories' => [
                [
                    'module_name' => 'lodash',
                    'severity' => 'high',
                    'title' => 'Prototype pollution',
                ],
            ],
            'summary' => [
                'vulnerabilities' => [
                    'high' => 1,
                ],
            ],
        ];

        $method->invokeArgs($analyzer, [$results, &$issues, 'yarn.lock']);

        // Only advisory issue should exist, no summary
        $this->assertCount(1, $issues);

        $issue = reset($issues);
        $this->assertNotFalse($issue);
        $this->assertEquals('vulnerability', $issue->metadata['issue_type']);
    }

    public function test_yarn_summary_metadata_contains_breakdown(): void
    {
        $analyzer = $this->createAnalyzer();

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('parseYarnAuditResults');
        $method->setAccessible(true);

        $issues = [];

        $results = [
            'summary' => [
                'vulnerabilities' => [
                    'low' => 1,
                    'moderate' => 2,
                ],
            ],
        ];

        $method->invokeArgs($analyzer, [$results, &$issues, 'yarn.lock']);

        $issue = reset($issues);
        $this->assertNotFalse($issue);
        $this->assertArrayHasKey('breakdown', $issue->metadata);
        $this->assertEquals(2, $issue->metadata['breakdown']['moderate']);
    }

    // ==================== Plain Text Parsing Tests ====================

    public function test_parses_npm_plain_text_output(): void
    {
        $analyzer = $this->createAnalyzer();

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('parseNpmPlainTextAudit');
        $method->setAccessible(true);

        $output = <<<'TEXT'
found 15 vulnerabilities (3 low, 8 moderate, 3 high, 1 critical)
run `npm audit fix` to fix them
TEXT;

        $result = $method->invoke($analyzer, $output);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('metadata', $result);
        $this->assertEquals(15, $result['metadata']['vulnerabilities']['total']);
    }

    public function test_parses_npm_plain_text_with_singular_vulnerability(): void
    {
        $analyzer = $this->createAnalyzer();

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('parseNpmPlainTextAudit');
        $method->setAccessible(true);

        $output = 'found 1 vulnerability (1 low)';

        $result = $method->invoke($analyzer, $output);

        $this->assertIsArray($result);
        $this->assertEquals(1, $result['metadata']['vulnerabilities']['total']);
    }

    public function test_parses_plain_text_with_no_vulnerabilities_as_a_zero_total(): void
    {
        $analyzer = $this->createAnalyzer();

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('parseNpmPlainTextAudit');
        $method->setAccessible(true);

        $output = 'found 0 vulnerabilities';

        $result = $method->invoke($analyzer, $output);

        // A clean audit, not an unreadable one: null now means the audit did not run.
        $this->assertIsArray($result);
        $this->assertEquals(0, $result['metadata']['vulnerabilities']['total']);
    }

    public function test_returns_null_for_plain_text_without_a_vulnerability_count(): void
    {
        $analyzer = $this->createAnalyzer();

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('parseNpmPlainTextAudit');
        $method->setAccessible(true);

        $this->assertNull($method->invoke($analyzer, 'npm ERR! code E403'));
    }

    // ==================== Result Format Tests ====================

    public function test_result_uses_result_by_severity(): void
    {
        $report = $this->npmAuditReport([
            'example-widget' => $this->npmVulnerability('example-widget', 'moderate', 'Regular expression denial of service in example-widget'),
        ]);

        $result = $this->analyzeWithFakeTool('npm', $report, 1);

        // A Medium issue alone grades as a warning, not a failure
        $this->assertWarning($result);
        $this->assertIssueCount(1, $result);
        $this->assertEquals(Severity::Medium, $result->getIssues()[0]->severity);
        $this->assertSame('Found 1 frontend dependency security issue', $result->getMessage());
    }

    public function test_summary_message_format_singular(): void
    {
        $packageJson = json_encode(['name' => 'test', 'dependencies' => ['vue' => '^3.0.0']]);

        $tempDir = $this->createTempDirectory([
            'package.json' => $packageJson,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Verify message is generated (singular form checked with missing lock file)
        $this->assertIsString($result->getMessage());
        $this->assertNotEmpty($result->getMessage());
    }

    // ==================== npm v7+ Parsing Tests ====================

    public function test_npm_v7_extracts_title_from_via_advisory_object(): void
    {
        $analyzer = $this->createAnalyzer();

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('parseNpmAuditResults');
        $method->setAccessible(true);

        $issues = [];

        $results = [
            'vulnerabilities' => [
                'ip-address' => [
                    'name' => 'ip-address',
                    'severity' => 'moderate',
                    'isDirect' => false,
                    'via' => [
                        [
                            'source' => 1117683,
                            'name' => 'ip-address',
                            'dependency' => 'ip-address',
                            'title' => 'ip-address has XSS in Address6 HTML-emitting methods',
                            'url' => 'https://github.com/advisories/GHSA-v2v4-37r5-5v8g',
                            'severity' => 'moderate',
                            'range' => '<=10.1.0',
                        ],
                    ],
                    'range' => '<=10.1.0',
                    'fixAvailable' => true,
                ],
            ],
        ];

        $method->invokeArgs($analyzer, [$results, &$issues, 'package-lock.json']);

        $this->assertCount(1, $issues);
        $issue = reset($issues);
        $this->assertNotFalse($issue);
        $this->assertStringContainsString('ip-address has XSS in Address6 HTML-emitting methods', $issue->message);
    }

    public function test_npm_v7_skips_transitive_only_vulnerabilities(): void
    {
        $analyzer = $this->createAnalyzer();

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('parseNpmAuditResults');
        $method->setAccessible(true);

        $issues = [];

        $results = [
            'vulnerabilities' => [
                'express-rate-limit' => [
                    'name' => 'express-rate-limit',
                    'severity' => 'moderate',
                    'isDirect' => false,
                    'via' => ['ip-address'], // strings only — transitive effect
                    'range' => '8.0.1 - 8.5.0',
                    'fixAvailable' => true,
                ],
            ],
        ];

        $method->invokeArgs($analyzer, [$results, &$issues, 'package-lock.json']);

        $this->assertCount(0, $issues);
    }

    public function test_npm_v7_multiple_via_advisories_create_multiple_issues(): void
    {
        $analyzer = $this->createAnalyzer();

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('parseNpmAuditResults');
        $method->setAccessible(true);

        $issues = [];

        $results = [
            'vulnerabilities' => [
                'some-package' => [
                    'name' => 'some-package',
                    'severity' => 'high',
                    'via' => [
                        [
                            'source' => 1001,
                            'title' => 'First vulnerability',
                            'severity' => 'high',
                        ],
                        [
                            'source' => 1002,
                            'title' => 'Second vulnerability',
                            'severity' => 'moderate',
                        ],
                    ],
                ],
            ],
        ];

        $method->invokeArgs($analyzer, [$results, &$issues, 'package-lock.json']);

        $this->assertCount(2, $issues);
    }

    public function test_npm_v7_falls_back_when_no_via(): void
    {
        $analyzer = $this->createAnalyzer();

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('parseNpmAuditResults');
        $method->setAccessible(true);

        $issues = [];

        $results = [
            'vulnerabilities' => [
                'old-package' => [
                    'name' => 'old-package',
                    'severity' => 'high',
                    'title' => 'Old format title',
                    // no 'via' key
                ],
            ],
        ];

        $method->invokeArgs($analyzer, [$results, &$issues, 'package-lock.json']);

        $this->assertCount(1, $issues);
        $issue = reset($issues);
        $this->assertNotFalse($issue);
        $this->assertStringContainsString('Old format title', $issue->message);
    }

    public function test_npm_v7_advisory_url_included_in_metadata(): void
    {
        $analyzer = $this->createAnalyzer();

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('parseNpmAuditResults');
        $method->setAccessible(true);

        $issues = [];

        $results = [
            'vulnerabilities' => [
                'ip-address' => [
                    'name' => 'ip-address',
                    'severity' => 'moderate',
                    'via' => [
                        [
                            'source' => 1117683,
                            'title' => 'ip-address has XSS in Address6 HTML-emitting methods',
                            'url' => 'https://github.com/advisories/GHSA-v2v4-37r5-5v8g',
                            'severity' => 'moderate',
                        ],
                    ],
                ],
            ],
        ];

        $method->invokeArgs($analyzer, [$results, &$issues, 'package-lock.json']);

        $this->assertCount(1, $issues);
        $issue = reset($issues);
        $this->assertNotFalse($issue);
        $this->assertArrayHasKey('advisory_url', $issue->metadata);
        $this->assertStringContainsString('GHSA-v2v4-37r5-5v8g', $issue->metadata['advisory_url']);
    }

    // ==================== Audit Not Run Tests ====================

    public function test_warns_when_npm_is_not_installed(): void
    {
        $result = $this->analyzeWithoutTool('package-lock.json', '{"lockfileVersion": 2}');

        $this->assertWarning($result);
        $this->assertIssueCount(0, $result);
        $this->assertStringContainsString('Frontend dependency audit did not run', $result->getMessage());
        $this->assertStringContainsString('npm was not found on PATH', $result->getMessage());
    }

    public function test_warns_when_yarn_is_not_installed(): void
    {
        $result = $this->analyzeWithoutTool('yarn.lock', '# yarn lockfile v1');

        $this->assertWarning($result);
        $this->assertIssueCount(0, $result);
        $this->assertStringContainsString('Frontend dependency audit did not run', $result->getMessage());
        $this->assertStringContainsString('yarn was not found on PATH', $result->getMessage());
    }

    /**
     * @param  array<int, string>  $expectedFragments
     *
     * @dataProvider auditNotRunOutputProvider
     */
    #[DataProvider('auditNotRunOutputProvider')]
    public function test_warns_when_audit_output_is_not_an_audit_result(
        string $tool,
        string $stdout,
        string $stderr,
        int $exitCode,
        array $expectedFragments
    ): void {
        $result = $this->analyzeWithFakeTool($tool, $stdout, $exitCode, $stderr);

        $this->assertWarning($result);
        $this->assertIssueCount(0, $result);
        $this->assertStringContainsString('Frontend dependency audit did not run', $result->getMessage());

        foreach ($expectedFragments as $fragment) {
            $this->assertStringContainsString($fragment, $result->getMessage());
        }

        // The project path never reaches the message, even when the tool echoes it.
        $this->assertStringNotContainsString('frontend-audit-project', $result->getMessage());
    }

    /**
     * @return array<string, array{string, string, string, int, array<int, string>}>
     */
    public static function auditNotRunOutputProvider(): array
    {
        return [
            'npm ENOAUDIT error JSON' => [
                'npm',
                '{"error":{"code":"ENOAUDIT","summary":"Your configured registry (https://registry.example.test/) does not support audit requests.","detail":""}}',
                '',
                1,
                ['npm audit returned ENOAUDIT', 'does not support audit requests'],
            ],
            'npm error JSON without a code' => [
                'npm',
                '{"error":{"summary":"audit endpoint returned an error"}}',
                '',
                1,
                ['npm audit returned an error', 'audit endpoint returned an error'],
            ],
            'npm non-JSON error output' => [
                'npm',
                "npm ERR! code E403 while auditing {base}/package-lock.json\nnpm ERR! 403 Forbidden - POST https://registry.example.test/-/npm/v1/security/audits/quick\n",
                '',
                1,
                ['npm audit output could not be parsed', 'npm ERR! code E403', './package-lock.json'],
            ],
            'npm JSON that is not an audit report' => [
                'npm',
                '{"name":"example-app","version":"1.0.0"}',
                '',
                0,
                ['npm audit output was not an audit report'],
            ],
            'npm empty stdout with stderr' => [
                'npm',
                '',
                "npm ERR! code ECONNREFUSED in {base}\n",
                1,
                ['npm audit produced no output (exit code 1)', 'npm ERR! code ECONNREFUSED in .'],
            ],
            'yarn error-only output' => [
                'yarn',
                "{\"type\":\"error\",\"data\":\"Error: https://registry.example.test/-/npm/v1/security/audits: Request failed \\\"404 Not Found\\\"\"}\n",
                '',
                1,
                ['yarn audit returned an error', '404 Not Found'],
            ],
            'yarn in offline mode' => [
                'yarn',
                "{\"type\":\"error\",\"data\":\"Can't make a request in offline mode (\\\"https://registry.example.test/-/npm/v1/security/audits\\\")\"}\n",
                '',
                1,
                ['yarn audit returned an error', "Can't make a request in offline mode"],
            ],
            'yarn output without an audit summary' => [
                'yarn',
                "{\"type\":\"info\",\"data\":\"Visit https://example.test for help\"}\n",
                '',
                0,
                ['yarn audit output had no audit summary'],
            ],
        ];
    }

    public function test_warns_when_audit_times_out(): void
    {
        $analyzer = $this->createAnalyzer();

        // Shrink the 60s limit so the fake tool outlives it within a couple of seconds.
        $property = (new \ReflectionClass($analyzer))->getProperty('auditTimeoutSeconds');
        $property->setAccessible(true);
        $property->setValue($analyzer, 1);

        $result = $this->analyzeWithFakeTool('npm', '', 0, '', $analyzer, 'exec /bin/sleep 10');

        $this->assertWarning($result);
        $this->assertIssueCount(0, $result);
        $this->assertStringContainsString('npm audit timed out after 1s', $result->getMessage());
    }

    public function test_fails_on_high_vulnerability_from_npm_audit(): void
    {
        $output = (string) json_encode([
            'auditReportVersion' => 2,
            'vulnerabilities' => [
                'example-widget' => [
                    'name' => 'example-widget',
                    'severity' => 'high',
                    'via' => [
                        ['source' => 9001, 'title' => 'Prototype pollution in example-widget', 'severity' => 'high'],
                    ],
                ],
            ],
            'metadata' => ['vulnerabilities' => ['info' => 0, 'low' => 0, 'moderate' => 0, 'high' => 1, 'critical' => 0, 'total' => 1]],
        ]);

        $result = $this->analyzeWithFakeTool('npm', $output, 1);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertEquals(Severity::High, $result->getIssues()[0]->severity);
        $this->assertHasIssueContaining('Prototype pollution in example-widget', $result);
    }

    public function test_passes_on_clean_npm_audit(): void
    {
        $output = (string) json_encode([
            'auditReportVersion' => 2,
            'vulnerabilities' => [],
            'metadata' => ['vulnerabilities' => ['info' => 0, 'low' => 0, 'moderate' => 0, 'high' => 0, 'critical' => 0, 'total' => 0]],
        ]);

        $result = $this->analyzeWithFakeTool('npm', $output, 0);

        $this->assertPassed($result);
        $this->assertSame('No vulnerable frontend dependencies detected', $result->getMessage());
    }

    public function test_passes_on_clean_npm_plain_text_audit(): void
    {
        $result = $this->analyzeWithFakeTool('npm', "found 0 vulnerabilities\n", 0);

        $this->assertPassed($result);
    }

    public function test_passes_on_clean_yarn_audit(): void
    {
        $output = '{"type":"auditSummary","data":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":0,"critical":0},"dependencies":12}}'."\n";

        $result = $this->analyzeWithFakeTool('yarn', $output, 0);

        $this->assertPassed($result);
    }

    // ==================== Lock File Coverage Tests ====================

    public function test_warns_when_stub_package_lock_covers_no_dependencies(): void
    {
        // npm 11 audits a lock with no packages, exits 0 and reports zero vulnerabilities.
        $report = (string) json_encode([
            'auditReportVersion' => 2,
            'vulnerabilities' => (object) [],
            'metadata' => [
                'vulnerabilities' => ['info' => 0, 'low' => 0, 'moderate' => 0, 'high' => 0, 'critical' => 0, 'total' => 0],
                'dependencies' => ['prod' => 1, 'dev' => 0, 'optional' => 0, 'peer' => 0, 'peerOptional' => 0, 'total' => 0],
            ],
        ]);

        $result = $this->analyzeWithFakeTool('npm', $report, projectFiles: [
            'package.json' => $this->packageJson(['example-widget' => '1.0.0']),
            'package-lock.json' => '{"lockfileVersion": 2}',
        ]);

        $this->assertWarning($result);
        $this->assertIssueCount(0, $result);
        $this->assertSame(
            'Frontend dependency audit did not cover the declared dependencies: package-lock.json is out of date and has no entry for example-widget; run "npm install" to update it',
            $result->getMessage()
        );
    }

    /**
     * @param  array<string, string>  $dependencies
     * @param  array<string, string>  $devDependencies
     * @param  array<int, string>  $locked
     *
     * @dataProvider npmLockMissingDependencyProvider
     */
    #[DataProvider('npmLockMissingDependencyProvider')]
    public function test_warns_when_package_lock_misses_a_declared_dependency(
        array $dependencies,
        array $devDependencies,
        array $locked,
        int $lockfileVersion,
        string $expectedMissing
    ): void {
        $result = $this->analyzeWithFakeTool('npm', $this->npmAuditReport(), projectFiles: [
            'package.json' => $this->packageJson($dependencies, $devDependencies),
            'package-lock.json' => $this->npmLock($locked, $lockfileVersion),
        ]);

        $this->assertWarning($result);
        $this->assertIssueCount(0, $result);
        $this->assertStringContainsString('package-lock.json is out of date and has no entry for '.$expectedMissing.';', $result->getMessage());
    }

    /**
     * @return array<string, array{array<string, string>, array<string, string>, array<int, string>, int, string}>
     */
    public static function npmLockMissingDependencyProvider(): array
    {
        return [
            'lockfile v3 missing a dependency' => [['example-number' => '7.0.0', 'example-widget' => '1.0.0'], [], ['example-number'], 3, 'example-widget'],
            'lockfile v2 missing a devDependency' => [['example-number' => '7.0.0'], ['example-builder' => '^2.0.0'], ['example-number'], 2, 'example-builder'],
            'lockfile v1 missing a dependency' => [['example-number' => '7.0.0', 'example-widget' => '1.0.0'], [], ['example-number'], 1, 'example-widget'],
            'scoped package missing' => [['@example/scoped' => '^1.0.0'], [], ['@example/other'], 3, '@example/scoped'],
            'a transitive copy does not count' => [['example-widget' => '1.0.0'], [], ['example-number/node_modules/example-widget'], 3, 'example-widget'],
            'several missing' => [['a-one' => '1', 'a-two' => '1', 'a-three' => '1', 'a-four' => '1', 'a-five' => '1', 'a-six' => '1', 'a-seven' => '1'], [], [], 3, 'a-one, a-two, a-three, a-four, a-five and 2 more'],
        ];
    }

    /**
     * @param  array<string, string>  $dependencies
     * @param  array<string, string>  $devDependencies
     * @param  array<int, string>  $locked
     *
     * @dataProvider npmLockCoversDeclaredDependenciesProvider
     */
    #[DataProvider('npmLockCoversDeclaredDependenciesProvider')]
    public function test_passes_when_package_lock_covers_declared_dependencies(
        array $dependencies,
        array $devDependencies,
        array $locked,
        int $lockfileVersion
    ): void {
        $result = $this->analyzeWithFakeTool('npm', $this->npmAuditReport(), projectFiles: [
            'package.json' => $this->packageJson($dependencies, $devDependencies),
            'package-lock.json' => $this->npmLock($locked, $lockfileVersion),
        ]);

        $this->assertPassed($result);
    }

    /**
     * @return array<string, array{array<string, string>, array<string, string>, array<int, string>, int}>
     */
    public static function npmLockCoversDeclaredDependenciesProvider(): array
    {
        return [
            'lockfile v3' => [['example-number' => '7.0.0'], [], ['example-number'], 3],
            'lockfile v3 devDependency' => [[], ['example-widget' => '1.0.0'], ['example-widget'], 3],
            'lockfile v2' => [['example-number' => '7.0.0'], ['example-widget' => '1.0.0'], ['example-number', 'example-widget'], 2],
            'lockfile v1' => [['example-number' => '7.0.0'], [], ['example-number'], 1],
            'scoped package' => [['@example/scoped' => '^1.0.0'], [], ['@example/scoped'], 3],
            'link: dependency is not locked' => [['example-number' => '7.0.0', 'example-local' => 'link:../local'], [], ['example-number'], 3],
        ];
    }

    public function test_out_of_date_lock_keeps_real_findings(): void
    {
        $report = $this->npmAuditReport([
            'example-number' => $this->npmVulnerability('example-number', 'high', 'Prototype pollution in example-number'),
        ]);

        $result = $this->analyzeWithFakeTool('npm', $report, 1, projectFiles: [
            'package.json' => $this->packageJson(['example-number' => '7.0.0', 'example-widget' => '1.0.0']),
            'package-lock.json' => $this->npmLock(['example-number']),
        ]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('Prototype pollution in example-number', $result);
    }

    public function test_unreadable_package_lock_is_not_called_out_of_date(): void
    {
        // A lock that is not JSON gives no evidence about what it holds, so the clean audit stands.
        $result = $this->analyzeWithFakeTool('npm', $this->npmAuditReport(), projectFiles: [
            'package.json' => $this->packageJson(['example-widget' => '1.0.0']),
            'package-lock.json' => 'not json',
        ]);

        $this->assertPassed($result);
    }

    public function test_warns_when_yarn_lock_misses_a_declared_dependency(): void
    {
        $summary = '{"type":"auditSummary","data":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":0,"critical":0},"dependencies":1}}'."\n";

        $result = $this->analyzeWithFakeTool('yarn', $summary, projectFiles: [
            'package.json' => $this->packageJson(['example-number' => '^7.0.0'], ['@example/scoped' => '^1.0.0']),
            'yarn.lock' => $this->yarnLock(['example-number@^7.0.0']),
        ]);

        $this->assertWarning($result);
        $this->assertIssueCount(0, $result);
        $this->assertSame(
            'Frontend dependency audit did not cover the declared dependencies: yarn.lock is out of date and has no entry for @example/scoped; run "yarn install" to update it',
            $result->getMessage()
        );
    }

    public function test_passes_when_yarn_lock_covers_declared_dependencies(): void
    {
        $summary = '{"type":"auditSummary","data":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":0,"critical":0},"dependencies":3}}'."\n";

        $result = $this->analyzeWithFakeTool('yarn', $summary, projectFiles: [
            'package.json' => $this->packageJson(
                ['example-number' => '^7.0.0', 'example-alias' => 'npm:example-widget@^1.0.0'],
                ['@example/scoped' => '^1.1.0']
            ),
            'yarn.lock' => $this->yarnLock([
                'example-number@^7.0.0',
                '"example-alias@npm:example-widget@^1.0.0"',
                '"@example/scoped@^1.0.0", "@example/scoped@^1.1.0"',
            ]),
        ]);

        $this->assertPassed($result);
    }

    public function test_yarn_workspace_root_is_not_called_out_of_date(): void
    {
        // yarn v1 never locks workspace packages, so a declared sibling has no entry by design.
        $summary = '{"type":"auditSummary","data":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":0,"critical":0},"dependencies":1}}'."\n";

        $result = $this->analyzeWithFakeTool('yarn', $summary, projectFiles: [
            'package.json' => (string) json_encode([
                'name' => 'example-monorepo',
                'private' => true,
                'workspaces' => ['packages/*'],
                'dependencies' => ['example-number' => '^7.0.0', 'example-sibling' => '1.0.0'],
            ]),
            'yarn.lock' => $this->yarnLock(['example-number@^7.0.0']),
        ]);

        $this->assertPassed($result);
    }

    // ==================== Offline Mode Tests ====================

    public function test_npm_audit_overrides_offline_mode(): void
    {
        // npm with offline=true in .npmrc or the environment prints a well-formed, empty report
        // and exits 0 without asking the registry. Only an explicit --offline=false overrides
        // both, so this fake npm answers with the real findings only when it is passed.
        $vulnerable = $this->npmAuditReport([
            'example-widget' => $this->npmVulnerability('example-widget', 'high', 'Prototype pollution in example-widget'),
        ]);
        $body = <<<'SH'
case "$*" in
  *--offline=false*) /bin/cat '{bin}/stdout.txt'; exit 1 ;;
  *) echo '{"auditReportVersion":2,"vulnerabilities":{},"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":0,"critical":0,"total":0}}}'; exit 0 ;;
esac
SH;

        $result = $this->analyzeWithFakeTool('npm', $vulnerable, body: $body, projectFiles: [
            'package.json' => $this->packageJson(['example-widget' => '1.0.0']),
            '.npmrc' => "offline=true\n",
            'package-lock.json' => $this->npmLock(['example-widget']),
        ]);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Prototype pollution in example-widget', $result);
    }

    public function test_npm_audit_includes_the_workspace_root(): void
    {
        // npm with workspaces=true (or workspace=<name>) in .npmrc or the environment audits only
        // the workspaces, so a vulnerable root dependency drops out of a well-formed, empty
        // report. Only an explicit --include-workspace-root=true brings the root back.
        $vulnerable = $this->npmAuditReport([
            'example-odd' => $this->npmVulnerability('example-odd', 'high', 'Prototype pollution in example-odd'),
        ]);
        $body = <<<'SH'
case "$*" in
  *--include-workspace-root=true*) /bin/cat '{bin}/stdout.txt'; exit 1 ;;
  *) echo '{"auditReportVersion":2,"vulnerabilities":{},"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":0,"critical":0,"total":0}}}'; exit 0 ;;
esac
SH;

        $files = $this->npmWorkspaceProject(['example-number' => '7.0.0']);
        $files['.npmrc'] = "workspaces=true\n";

        $result = $this->analyzeWithFakeTool('npm', $vulnerable, body: $body, projectFiles: $files);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Prototype pollution in example-odd', $result);
    }

    // ==================== npm Workspace Tests ====================

    public function test_warns_when_workspace_dependency_is_missing_from_lock(): void
    {
        $result = $this->analyzeWithFakeTool('npm', $this->npmAuditReport(), projectFiles: [
            'package.json' => '{"name":"root","private":true,"workspaces":["packages/*"],"devDependencies":{"vite":"^5.0.0"}}',
            'packages/a/package.json' => '{"name":"@app/a","version":"1.0.0","dependencies":{"lodash":"4.17.4"}}',
            'package-lock.json' => (string) json_encode([
                'name' => 'root',
                'lockfileVersion' => 3,
                'requires' => true,
                'packages' => [
                    '' => ['name' => 'root', 'workspaces' => ['packages/*'], 'devDependencies' => ['vite' => '^5.0.0']],
                    'node_modules/vite' => ['version' => '5.0.0', 'dev' => true],
                    'packages/a' => ['name' => '@app/a', 'version' => '1.0.0'],
                    'node_modules/@app/a' => ['resolved' => 'packages/a', 'link' => true],
                ],
            ]),
        ]);

        $this->assertWarning($result);
        $this->assertIssueCount(0, $result);
        $this->assertSame(
            'Frontend dependency audit did not cover the declared dependencies: package-lock.json is out of date and has no entry for lodash (packages/a); run "npm install" to update it',
            $result->getMessage()
        );
    }

    public function test_warns_when_workspace_gained_a_dependency_after_install(): void
    {
        // The npm 11 shape of a workspace whose package.json gained lodash after `npm install`.
        $result = $this->analyzeWithFakeTool('npm', $this->npmAuditReport(), projectFiles: $this->npmWorkspaceProject(
            ['example-number' => '7.0.0', 'lodash' => '4.17.4']
        ));

        $this->assertWarning($result);
        $this->assertStringContainsString('has no entry for lodash (packages/a);', $result->getMessage());
    }

    public function test_passes_when_workspace_dependencies_are_locked(): void
    {
        // Nested under the workspace (example-number) or hoisted to the root (example-widget)
        $result = $this->analyzeWithFakeTool('npm', $this->npmAuditReport(), projectFiles: $this->npmWorkspaceProject(
            ['example-number' => '7.0.0', 'example-widget' => '^1.0.0', '@app/b' => '^1.0.0']
        ));

        $this->assertPassed($result);
    }

    public function test_warns_when_workspace_folder_is_missing_from_lock(): void
    {
        $files = $this->npmWorkspaceProject(['example-number' => '7.0.0']);
        $files['packages/c/package.json'] = '{"name":"@app/c","version":"1.0.0"}';

        $result = $this->analyzeWithFakeTool('npm', $this->npmAuditReport(), projectFiles: $files);

        $this->assertWarning($result);
        $this->assertStringContainsString('has no entry for workspace packages/c;', $result->getMessage());
    }

    public function test_reads_workspaces_in_object_form_and_honours_negation(): void
    {
        $files = $this->npmWorkspaceProject(['example-number' => '7.0.0', 'lodash' => '4.17.4']);
        $files['package.json'] = '{"name":"root","private":true,"workspaces":{"packages":["packages/*","!packages/b"]},"devDependencies":{"example-odd":"3.0.1"}}';
        // Excluded by the negation, so neither its folder nor its dependency is expected in the lock
        $files['packages/b/package.json'] = '{"name":"@app/b","version":"1.0.0","dependencies":{"example-unlocked":"1.0.0"}}';

        $result = $this->analyzeWithFakeTool('npm', $this->npmAuditReport(), projectFiles: $files);

        $this->assertWarning($result);
        $this->assertStringContainsString('has no entry for lodash (packages/a);', $result->getMessage());
        $this->assertStringNotContainsString('packages/b', $result->getMessage());
    }

    // ==================== Advisory Severity Tests ====================

    public function test_yarn_info_advisory_maps_to_low_severity(): void
    {
        $issues = $this->parseAdvisories('parseYarnAuditResults', [
            'advisories' => [
                ['module_name' => 'example-widget', 'severity' => 'info', 'title' => 'Informational advisory'],
            ],
        ]);

        $this->assertCount(1, $issues);
        $this->assertEquals(Severity::Low, $issues[0]->severity);
    }

    public function test_npm_v7_info_advisory_maps_to_low_severity(): void
    {
        $issues = $this->parseAdvisories('parseNpmAuditResults', [
            'vulnerabilities' => [
                'example-widget' => [
                    'name' => 'example-widget',
                    'severity' => 'info',
                    'via' => [['source' => 9002, 'title' => 'Informational advisory', 'severity' => 'info']],
                ],
            ],
        ]);

        $this->assertCount(1, $issues);
        $this->assertEquals(Severity::Low, $issues[0]->severity);
    }

    public function test_advisory_without_severity_maps_to_high(): void
    {
        $issues = $this->parseAdvisories('parseNpmAuditResults', [
            'advisories' => [
                '9003' => ['module_name' => 'example-widget', 'title' => 'Advisory with no severity'],
            ],
        ]);

        $this->assertCount(1, $issues);
        $this->assertEquals(Severity::High, $issues[0]->severity);
    }

    public function test_advisory_with_unrecognised_severity_maps_to_high(): void
    {
        $issues = $this->parseAdvisories('parseYarnAuditResults', [
            'advisories' => [
                ['module_name' => 'example-widget', 'severity' => 'severe', 'title' => 'Advisory with an unknown level'],
            ],
        ]);

        $this->assertCount(1, $issues);
        $this->assertEquals(Severity::High, $issues[0]->severity);
    }

    public function test_critical_advisory_stays_critical(): void
    {
        $issues = $this->parseAdvisories('parseNpmAuditResults', [
            'vulnerabilities' => [
                'example-widget' => [
                    'name' => 'example-widget',
                    'severity' => 'critical',
                    'via' => [['source' => 9004, 'title' => 'Remote code execution', 'severity' => 'critical']],
                ],
            ],
        ]);

        $this->assertCount(1, $issues);
        $this->assertEquals(Severity::Critical, $issues[0]->severity);
    }

    // ==================== Helper Methods ====================

    /**
     * Invoke one of the analyzer's private advisory parsers on a decoded payload.
     *
     * @param  array<array-key, mixed>  $results
     * @return array<int, Issue>
     */
    private function parseAdvisories(string $parser, array $results): array
    {
        $analyzer = $this->createAnalyzer();

        $method = (new \ReflectionClass($analyzer))->getMethod($parser);
        $method->setAccessible(true);

        $issues = [];
        $lockFile = $parser === 'parseYarnAuditResults' ? 'yarn.lock' : 'package-lock.json';
        $method->invokeArgs($analyzer, [$results, &$issues, $lockFile]);

        return $issues;
    }

    /**
     * Analyze a project whose lock file selects $tool, with PATH holding no tools at all.
     */
    private function analyzeWithoutTool(string $lockFile, string $lockContents): ResultInterface
    {
        $projectDir = $this->createProject([
            'package.json' => $this->packageJson(['example-widget' => '1.0.0']),
            $lockFile => $lockContents,
        ]);
        $emptyBinDir = $this->createTempDirectory(['.keep' => '']);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($projectDir);
        $analyzer->setPaths(['.']);

        return $this->withPath($emptyBinDir, fn () => $analyzer->analyze());
    }

    /**
     * Analyze a project against a fake npm or yarn that prints canned output.
     *
     * PATH holds only the fake tool, so no test reaches the host's npm or yarn or the network.
     * "{base}" in $stdout or $stderr is replaced with the project directory, to model a tool
     * that echoes the path it ran in, and "{bin}" in $body with the fake tool's directory,
     * which holds stdout.txt and stderr.txt. Without $projectFiles the project declares
     * example-widget and has a lock file for $tool that holds it.
     *
     * @param  array<string, string>|null  $projectFiles  path => contents, relative to the project
     */
    private function analyzeWithFakeTool(
        string $tool,
        string $stdout,
        int $exitCode = 0,
        string $stderr = '',
        ?AnalyzerInterface $analyzer = null,
        ?string $body = null,
        ?array $projectFiles = null
    ): ResultInterface {
        $projectDir = $this->createProject($projectFiles ?? [
            'package.json' => $this->packageJson(['example-widget' => '1.0.0']),
            $tool === 'npm' ? 'package-lock.json' : 'yarn.lock' => $tool === 'npm'
                ? $this->npmLock(['example-widget'])
                : $this->yarnLock(['example-widget@1.0.0']),
        ]);

        $binDir = $this->createTempDirectory([
            'stdout.txt' => str_replace('{base}', $projectDir, $stdout),
            'stderr.txt' => str_replace('{base}', $projectDir, $stderr),
        ]);
        $script = $body !== null ? str_replace('{bin}', $binDir, $body) : sprintf(
            "/bin/cat '%s/stdout.txt'\n/bin/cat '%s/stderr.txt' >&2\nexit %d",
            $binDir,
            $binDir,
            $exitCode
        );
        file_put_contents($binDir.'/'.$tool, "#!/bin/sh\n".$script."\n");
        chmod($binDir.'/'.$tool, 0755);

        $analyzer ??= $this->createAnalyzer();
        $analyzer->setBasePath($projectDir);
        $analyzer->setPaths(['.']);

        return $this->withPath($binDir, fn () => $analyzer->analyze());
    }

    /**
     * Create a project directory whose path is known not to appear in any fixture text.
     *
     * @param  array<string, string>  $files
     */
    private function createProject(array $files): string
    {
        $prefixed = [];
        foreach ($files as $path => $contents) {
            $prefixed['frontend-audit-project/'.$path] = $contents;
        }

        return $this->createTempDirectory($prefixed).'/frontend-audit-project';
    }

    /**
     * @param  array<string, string>  $dependencies
     * @param  array<string, string>  $devDependencies
     */
    private function packageJson(array $dependencies, array $devDependencies = []): string
    {
        $package = ['name' => 'example-app', 'version' => '1.0.0'];
        if ($dependencies !== []) {
            $package['dependencies'] = $dependencies;
        }
        if ($devDependencies !== []) {
            $package['devDependencies'] = $devDependencies;
        }

        return (string) json_encode($package);
    }

    /**
     * A package-lock.json in the shape npm 7+ writes (lockfileVersion 2 or 3, a "packages"
     * map keyed by install path), or lockfileVersion 1 (a "dependencies" map keyed by name).
     *
     * @param  array<int, string>  $names
     */
    private function npmLock(array $names, int $lockfileVersion = 3): string
    {
        if ($lockfileVersion === 1) {
            $dependencies = [];
            foreach ($names as $name) {
                $dependencies[$name] = ['version' => '1.0.0'];
            }

            return (string) json_encode(['name' => 'example-app', 'lockfileVersion' => 1, 'requires' => true, 'dependencies' => $dependencies]);
        }

        $packages = ['' => ['name' => 'example-app', 'version' => '1.0.0']];
        foreach ($names as $name) {
            $packages['node_modules/'.$name] = ['version' => '1.0.0', 'license' => 'MIT'];
        }

        return (string) json_encode(['name' => 'example-app', 'lockfileVersion' => $lockfileVersion, 'requires' => true, 'packages' => $packages]);
    }

    /**
     * A yarn v1 lock file with one entry per "name@range" key list.
     *
     * @param  array<int, string>  $keys  e.g. "example-widget@^1.0.0" or "\"@example/scoped@^1.0.0\", \"@example/scoped@^1.1.0\""
     */
    private function yarnLock(array $keys): string
    {
        $lock = "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n";
        foreach ($keys as $key) {
            $lock .= "\n\n".$key.":\n  version \"1.0.0\"\n  resolved \"https://registry.example.test/pkg-1.0.0.tgz\"\n";
        }

        return $lock;
    }

    /**
     * An npm v7+ audit report.
     *
     * @param  array<string, array<string, mixed>>  $vulnerabilities  package => vulnerability entry
     */
    private function npmAuditReport(array $vulnerabilities = []): string
    {
        $counts = ['info' => 0, 'low' => 0, 'moderate' => 0, 'high' => 0, 'critical' => 0];
        foreach ($vulnerabilities as $vulnerability) {
            $severity = $vulnerability['severity'] ?? null;
            if (is_string($severity) && isset($counts[$severity])) {
                $counts[$severity]++;
            }
        }
        $counts['total'] = count($vulnerabilities);

        return (string) json_encode([
            'auditReportVersion' => 2,
            'vulnerabilities' => (object) $vulnerabilities,
            'metadata' => ['vulnerabilities' => $counts],
        ]);
    }

    /**
     * One npm v7+ vulnerability entry with a single advisory.
     *
     * @return array<string, mixed>
     */
    private function npmVulnerability(string $package, string $severity, string $title, int $source = 9100): array
    {
        return [
            'name' => $package,
            'severity' => $severity,
            'isDirect' => true,
            'via' => [[
                'source' => $source,
                'name' => $package,
                'dependency' => $package,
                'title' => $title,
                'url' => 'https://github.com/advisories/GHSA-xxxx-'.$source,
                'severity' => $severity,
                'range' => '<1.0.1',
            ]],
            'range' => '<1.0.1',
            'fixAvailable' => true,
        ];
    }

    /**
     * An npm workspace project in the shape npm 11 locks it: a root declaring workspaces
     * "packages/*" and a devDependency, workspace packages/a declaring $workspaceDependencies,
     * and workspace packages/b. The lock holds example-number nested under packages/a, and
     * example-widget and example-odd hoisted to the root.
     *
     * @param  array<string, string>  $workspaceDependencies
     * @return array<string, string>
     */
    private function npmWorkspaceProject(array $workspaceDependencies): array
    {
        return [
            'package.json' => '{"name":"root","version":"1.0.0","private":true,"workspaces":["packages/*"],"dependencies":{"@app/a":"^1.0.0"},"devDependencies":{"example-odd":"3.0.1"}}',
            'packages/a/package.json' => (string) json_encode(['name' => '@app/a', 'version' => '1.0.0', 'dependencies' => $workspaceDependencies]),
            'packages/b/package.json' => '{"name":"@app/b","version":"1.0.0"}',
            'package-lock.json' => (string) json_encode([
                'name' => 'root',
                'version' => '1.0.0',
                'lockfileVersion' => 3,
                'requires' => true,
                'packages' => [
                    '' => ['name' => 'root', 'version' => '1.0.0', 'workspaces' => ['packages/*'], 'dependencies' => ['@app/a' => '^1.0.0'], 'devDependencies' => ['example-odd' => '3.0.1']],
                    'node_modules/@app/a' => ['resolved' => 'packages/a', 'link' => true],
                    'node_modules/@app/b' => ['resolved' => 'packages/b', 'link' => true],
                    'node_modules/example-odd' => ['version' => '3.0.1', 'dev' => true, 'license' => 'MIT'],
                    'node_modules/example-widget' => ['version' => '1.0.0', 'license' => 'MIT'],
                    'packages/a' => ['name' => '@app/a', 'version' => '1.0.0', 'dependencies' => ['example-number' => '7.0.0']],
                    'packages/a/node_modules/example-number' => ['version' => '7.0.0', 'license' => 'MIT'],
                    'packages/b' => ['name' => '@app/b', 'version' => '1.0.0'],
                ],
            ]),
        ];
    }

    /**
     * Run a callback with PATH set to a single directory, restoring it afterwards.
     *
     * @param  callable(): ResultInterface  $callback
     */
    private function withPath(string $path, callable $callback): ResultInterface
    {
        $originalPath = getenv('PATH');
        putenv('PATH='.$path);

        try {
            return $callback();
        } finally {
            putenv('PATH='.($originalPath === false ? '' : $originalPath));
        }
    }

    // =========================================================================
    // Vapor / Serverless Skip Tests
    // =========================================================================

    public function test_skips_on_vapor(): void
    {
        /** @var FrontendVulnerableDependencyAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setDeploymentPlatform('vapor');

        $this->assertFalse($analyzer->shouldRun());
        $this->assertStringContainsString('Vapor', $analyzer->getSkipReason());
    }

    public function test_skips_on_serverless(): void
    {
        /** @var FrontendVulnerableDependencyAnalyzer $analyzer */
        $analyzer = $this->createAnalyzer();
        $analyzer->setDeploymentPlatform('serverless');

        $this->assertFalse($analyzer->shouldRun());
    }
}
