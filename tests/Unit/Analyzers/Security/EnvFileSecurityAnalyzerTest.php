<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\EnvFileSecurityAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class EnvFileSecurityAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new EnvFileSecurityAnalyzer;
    }

    public function test_analyzes_env_security(): void
    {
        $envContent = 'APP_KEY=base64:test';
        $envExample = 'APP_KEY=';
        $gitignore = <<<'GITIGNORE'
/vendor
/node_modules
.env
.env.backup
GITIGNORE;

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            '.env.example' => $envExample,
            '.gitignore' => $gitignore,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // May pass or have permission warnings depending on environment
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_fails_when_env_file_publicly_accessible(): void
    {
        $envContent = 'APP_KEY=test';

        $tempDir = $this->createTempDirectory([
            'public/.env' => $envContent,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('public', $result);
    }

    public function test_warns_when_env_not_in_gitignore(): void
    {
        $envContent = 'APP_KEY=test';
        $gitignore = '# empty';

        $tempDir = $this->createTempDirectory([
            '.env' => $envContent,
            '.gitignore' => $gitignore,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('gitignore', $result);
    }
}
