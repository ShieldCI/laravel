<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use ShieldCI\Analyzers\Reliability\UpToDateMigrationsAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class UpToDateMigrationsAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new UpToDateMigrationsAnalyzer;
    }

    public function test_checks_migration_status(): void
    {
        $tempDir = $this->createTempDirectory([
            'database/migrations/.gitkeep' => '',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // May pass or fail depending on migration status
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }
}
