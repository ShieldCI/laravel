<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\HashingStrengthAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class HashingStrengthAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new HashingStrengthAnalyzer;
    }

    public function test_passes_with_secure_bcrypt_configuration(): void
    {
        $config = <<<'PHP'
<?php

return [
    'driver' => 'bcrypt',
    'bcrypt' => [
        'rounds' => 12,
    ],
];
PHP;

        $tempDir = $this->createTempDirectory(['config/hashing.php' => $config]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_bcrypt_rounds_too_low(): void
    {
        $config = <<<'PHP'
<?php

return [
    'driver' => 'bcrypt',
    'bcrypt' => [
        'rounds' => 10,
    ],
];
PHP;

        $tempDir = $this->createTempDirectory(['config/hashing.php' => $config]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Bcrypt rounds', $result);
    }

    public function test_fails_when_argon2_memory_too_low(): void
    {
        $config = <<<'PHP'
<?php

return [
    'driver' => 'argon2id',
    'argon' => [
        'memory' => 1024,
        'time' => 2,
        'threads' => 2,
    ],
];
PHP;

        $tempDir = $this->createTempDirectory(['config/hashing.php' => $config]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Argon2 memory', $result);
    }

    public function test_fails_when_using_weak_hash_driver(): void
    {
        $config = <<<'PHP'
<?php

return [
    'driver' => 'md5',
];
PHP;

        $tempDir = $this->createTempDirectory(['config/hashing.php' => $config]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Weak hashing driver', $result);
    }

    public function test_detects_weak_hashing_in_code(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $password = md5($request->password);
        User::create(['password' => $password]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Weak hashing function', $result);
    }

    public function test_detects_plain_text_password_storage(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function store($request)
    {
        $user->password = $request->password;
        $user->save();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('plain-text password', $result);
    }
}
