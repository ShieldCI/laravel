<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use ShieldCI\Analyzers\CodeQuality\NestingDepthAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class NestingDepthAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new NestingDepthAnalyzer($this->parser);
    }

    public function test_detects_deep_nesting(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ValidationService
{
    public function validate($data)
    {
        if ($data) {
            if ($data['user']) {
                if ($data['user']['email']) {
                    if (filter_var($data['user']['email'], FILTER_VALIDATE_EMAIL)) {
                        if ($data['user']['age'] > 18) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/ValidationService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('nesting depth', $result);
    }

    public function test_passes_with_guard_clauses(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ValidationService
{
    public function validate($data)
    {
        if (!$data) {
            return false;
        }

        if (!isset($data['user'])) {
            return false;
        }

        if (!isset($data['user']['email'])) {
            return false;
        }

        return filter_var($data['user']['email'], FILTER_VALIDATE_EMAIL);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/ValidationService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
