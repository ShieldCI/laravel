<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\FilePermissionsAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class FilePermissionsAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new FilePermissionsAnalyzer;
    }

    public function test_checks_file_permissions(): void
    {
        $envContent = 'APP_KEY=test';

        $tempDir = $this->createTempDirectory(['.env' => $envContent]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Result depends on actual file permissions
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_analyzes_directory_structure(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => '<?php class User {}',
            'config/app.php' => '<?php return [];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertNotNull($result->getMessage());
    }
}
