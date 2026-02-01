<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use Mockery;
use ShieldCI\Analyzers\Reliability\ComposerValidationAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Support\ComposerValidator;
use ShieldCI\Support\ComposerValidatorResult;
use ShieldCI\Tests\AnalyzerTestCase;

class ComposerValidationAnalyzerTest extends AnalyzerTestCase
{
    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    protected function createAnalyzer(?ComposerValidator $validator = null): AnalyzerInterface
    {
        return new ComposerValidationAnalyzer($validator ?? new ComposerValidator);
    }

    public function test_fails_when_composer_json_missing(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('composer.json file is missing', $result);
    }

    public function test_fails_with_invalid_json(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => '{invalid}',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_passes_when_validation_succeeds(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => '{"name":"shieldci/demo"}',
        ]);

        /** @var ComposerValidator&\Mockery\MockInterface $validator */
        $validator = Mockery::mock(ComposerValidator::class);
        $validator->shouldReceive('validate')
            ->andReturn(new ComposerValidatorResult(true, 'composer.json is valid'));

        $analyzer = $this->createAnalyzer($validator);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_composer_validate_reports_errors(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => '{"name":"shieldci/demo"}',
        ]);

        /** @var ComposerValidator&\Mockery\MockInterface $validator */
        $validator = Mockery::mock(ComposerValidator::class);
        $validator->shouldReceive('validate')
            ->andReturn(new ComposerValidatorResult(false, 'composer.json is invalid'));

        $analyzer = $this->createAnalyzer($validator);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('composer validate command reported issues', $result);
    }

    // =========================================================================
    // JSON Syntax Error Tests
    // =========================================================================

    public function test_fails_with_trailing_comma(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => '{"name":"shieldci/demo",}',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not valid JSON', $result);
    }

    public function test_fails_with_missing_comma(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => '{"name":"shieldci/demo" "type":"project"}',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not valid JSON', $result);
    }

    public function test_fails_with_unquoted_key(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => '{name:"shieldci/demo"}',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not valid JSON', $result);
    }

    public function test_fails_with_single_quoted_string(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => "{'name':'shieldci/demo'}",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('not valid JSON', $result);
    }

    // =========================================================================
    // JSON Structure Validation Tests
    // =========================================================================

    public function test_fails_with_json_array(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => '["name","type"]',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('must be a JSON object', $result);
    }

    public function test_fails_with_json_string(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => '"shieldci/demo"',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('must be a JSON object', $result);
    }

    public function test_fails_with_json_number(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => '123',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('must be a JSON object', $result);
    }

    public function test_passes_with_empty_json_object(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => '{}',
        ]);

        /** @var ComposerValidator&\Mockery\MockInterface $validator */
        $validator = Mockery::mock(ComposerValidator::class);
        $validator->shouldReceive('validate')
            ->andReturn(new ComposerValidatorResult(true, 'composer.json is valid'));

        $analyzer = $this->createAnalyzer($validator);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // =========================================================================
    // File Read Failure Tests
    // =========================================================================

    public function test_handles_unreadable_composer_json(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => '{"name":"shieldci/demo"}',
        ]);

        $composerPath = $tempDir.'/composer.json';

        // Make file unreadable
        chmod($composerPath, 0000);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Restore permissions for cleanup
        chmod($composerPath, 0644);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('cannot be read', $result);
    }

    // =========================================================================
    // Composer Validation Edge Cases
    // =========================================================================

    public function test_passes_with_minimal_valid_composer_json(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => '{"name":"vendor/package"}',
        ]);

        /** @var ComposerValidator&\Mockery\MockInterface $validator */
        $validator = Mockery::mock(ComposerValidator::class);
        $validator->shouldReceive('validate')
            ->andReturn(new ComposerValidatorResult(true, 'composer.json is valid'));

        $analyzer = $this->createAnalyzer($validator);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_includes_composer_output_in_metadata(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => '{"name":"shieldci/demo"}',
        ]);

        /** @var ComposerValidator&\Mockery\MockInterface $validator */
        $validator = Mockery::mock(ComposerValidator::class);
        $validator->shouldReceive('validate')
            ->andReturn(new ComposerValidatorResult(false, 'name is required'));

        $analyzer = $this->createAnalyzer($validator);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertArrayHasKey('composer_output', $issues[0]->metadata);
        $this->assertEquals('name is required', $issues[0]->metadata['composer_output']);
    }

    public function test_includes_json_error_in_metadata(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => '{invalid json}',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertArrayHasKey('json_error', $issues[0]->metadata);
        $this->assertNotEmpty($issues[0]->metadata['json_error']);
    }

    public function test_location_points_to_composer_json(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => '{invalid}',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertNotNull($issues[0]->location);
        $this->assertStringContainsString('composer.json', $issues[0]->location->file);
    }
}
