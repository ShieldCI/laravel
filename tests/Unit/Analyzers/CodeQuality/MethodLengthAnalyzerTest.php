<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use ShieldCI\Analyzers\CodeQuality\MethodLengthAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class MethodLengthAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new MethodLengthAnalyzer($this->parser);
    }

    public function test_detects_long_methods(): void
    {
        $statements = str_repeat('        $var = "value";'."\n", 60);

        $code = <<<PHP
<?php

namespace App\Services;

class DataProcessor
{
    public function processData(\$input)
    {
{$statements}
        return \$var;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/DataProcessor.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('lines', $result);
    }

    public function test_passes_with_short_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getName($user)
    {
        return $user->name ?? 'Unknown';
    }

    public function getEmail($user)
    {
        return $user->email;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
