<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use ShieldCI\Analyzers\CodeQuality\TodoCommentAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class TodoCommentAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new TodoCommentAnalyzer;
    }

    public function test_detects_todo_comments(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function register($data)
    {
        // TODO: Add email verification
        $user = User::create($data);

        // FIXME: This validation is broken
        // HACK: Temporary workaround
        return $user;
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

        $this->assertWarning($result);
        $this->assertHasIssueContaining('TODO', $result);
    }

    public function test_passes_without_todo_comments(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    /**
     * Register a new user.
     */
    public function register($data)
    {
        return User::create($data);
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
