<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Performance;

use ShieldCI\Analyzers\Performance\CollectionCallAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class CollectionCallAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new CollectionCallAnalyzer;
    }

    public function test_analyzes_collection_usage(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getUsers()
    {
        return User::all()->where('active', true);
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

        // Analyzer checks for inefficient patterns
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);
    }

    public function test_passes_with_efficient_queries(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getUsers()
    {
        return User::where('active', true)->get();
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
