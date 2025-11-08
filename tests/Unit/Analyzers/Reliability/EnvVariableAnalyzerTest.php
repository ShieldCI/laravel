<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Reliability;

use ShieldCI\Analyzers\Reliability\EnvVariableAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class EnvVariableAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new EnvVariableAnalyzer;
    }

    public function test_fails_when_env_file_missing(): void
    {
        $exampleContent = 'APP_NAME=Laravel
APP_ENV=local
APP_KEY=
DB_CONNECTION=mysql';

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('missing', $result);
    }

    public function test_fails_when_variables_missing(): void
    {
        $exampleContent = 'APP_NAME=Laravel
APP_ENV=local
APP_KEY=
DB_CONNECTION=mysql
DB_HOST=127.0.0.1';

        $envContent = 'APP_NAME=Laravel
APP_ENV=local';

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Missing environment variables', $result);
    }

    public function test_passes_with_all_variables_present(): void
    {
        $exampleContent = 'APP_NAME=Laravel
APP_ENV=local
APP_KEY=base64:test123';

        $envContent = 'APP_NAME=MyApp
APP_ENV=production
APP_KEY=base64:real_key_here';

        $tempDir = $this->createTempDirectory([
            '.env.example' => $exampleContent,
            '.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
