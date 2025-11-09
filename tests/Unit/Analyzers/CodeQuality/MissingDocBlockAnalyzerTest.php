<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use ShieldCI\Analyzers\CodeQuality\MissingDocBlockAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class MissingDocBlockAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new MissingDocBlockAnalyzer($this->parser);
    }

    public function test_detects_missing_docblocks(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function processUser($userId, $action)
    {
        return User::find($userId);
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

        $this->assertFailed($result);
        $this->assertHasIssueContaining('PHPDoc', $result);
    }

    public function test_passes_with_proper_docblocks(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    /**
     * Process a user action.
     *
     * @param int $userId
     * @param string $action
     * @return User|null
     */
    public function processUser($userId, $action)
    {
        return User::find($userId);
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
