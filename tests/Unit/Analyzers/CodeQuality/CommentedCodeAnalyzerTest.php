<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use ShieldCI\Analyzers\CodeQuality\CommentedCodeAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class CommentedCodeAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new CommentedCodeAnalyzer;
    }

    public function test_detects_commented_code(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function register($data)
    {
        $user = User::create($data);

        // Old implementation:
        // $validator = new UserValidator();
        // if (!$validator->validate($data)) {
        //     throw new ValidationException();
        // }
        // $user = new User();
        // $user->name = $data['name'];

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

        $this->assertFailed($result);
        $this->assertHasIssueContaining('commented-out code', $result);
    }

    public function test_passes_without_commented_code(): void
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
        // Validate the input data
        $validated = $this->validate($data);

        return User::create($validated);
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
