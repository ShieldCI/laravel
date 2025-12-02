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
}
