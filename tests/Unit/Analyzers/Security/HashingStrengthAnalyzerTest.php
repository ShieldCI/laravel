<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\HashingStrengthAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class HashingStrengthAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new HashingStrengthAnalyzer;
    }

    // ==================== Basic Functionality Tests ====================

    public function test_should_run_returns_false_when_no_hashing_config(): void
    {
        $tempDir = $this->createTempDirectory([
            'composer.json' => '{}',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertFalse($analyzer->shouldRun());
    }

    public function test_should_run_returns_true_when_hashing_config_exists(): void
    {
        $tempDir = $this->createTempDirectory([
            'config/hashing.php' => '<?php return [];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_get_skip_reason_returns_correct_message(): void
    {
        $analyzer = $this->createAnalyzer();

        $reason = $analyzer->getSkipReason();

        $this->assertStringContainsString('No hashing configuration file found', $reason);
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

    public function test_passes_with_secure_argon2_configuration(): void
    {
        $config = <<<'PHP'
<?php

return [
    'driver' => 'argon2id',
    'argon' => [
        'memory' => 65536,
        'time' => 2,
        'threads' => 2,
    ],
];
PHP;

        $tempDir = $this->createTempDirectory(['config/hashing.php' => $config]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ==================== Bcrypt Configuration Tests ====================

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

    public function test_bcrypt_rounds_issue_has_critical_severity(): void
    {
        $config = <<<'PHP'
<?php

return [
    'bcrypt' => [
        'rounds' => 10,
    ],
];
PHP;

        $tempDir = $this->createTempDirectory(['config/hashing.php' => $config]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(Severity::Critical, $issues[0]->severity);
    }

    public function test_bcrypt_rounds_metadata_includes_value(): void
    {
        $config = <<<'PHP'
<?php

return [
    'bcrypt' => [
        'rounds' => 8,
    ],
];
PHP;

        $tempDir = $this->createTempDirectory(['config/hashing.php' => $config]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertArrayHasKey('rounds', $issues[0]->metadata);
        $this->assertEquals(8, $issues[0]->metadata['rounds']);
    }

    // ==================== Argon2 Configuration Tests ====================

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

    public function test_argon2_memory_issue_has_critical_severity(): void
    {
        $config = <<<'PHP'
<?php

return [
    'argon' => [
        'memory' => 1024,
    ],
];
PHP;

        $tempDir = $this->createTempDirectory(['config/hashing.php' => $config]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(Severity::Critical, $issues[0]->severity);
    }

    public function test_fails_when_argon2_time_too_low(): void
    {
        $config = <<<'PHP'
<?php

return [
    'argon' => [
        'memory' => 65536,
        'time' => 1,
    ],
];
PHP;

        $tempDir = $this->createTempDirectory(['config/hashing.php' => $config]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Argon2 time cost', $result);
    }

    public function test_argon2_time_issue_has_medium_severity(): void
    {
        $config = <<<'PHP'
<?php

return [
    'argon' => [
        'time' => 1,
    ],
];
PHP;

        $tempDir = $this->createTempDirectory(['config/hashing.php' => $config]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(Severity::Medium, $issues[0]->severity);
    }

    public function test_detects_argon2_threads_too_low(): void
    {
        $config = <<<'PHP'
<?php

return [
    'argon' => [
        'memory' => 65536,
        'time' => 2,
        'threads' => 1,
    ],
];
PHP;

        $tempDir = $this->createTempDirectory(['config/hashing.php' => $config]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        // Low severity results in Warning status
        $this->assertWarning($result);
        $this->assertHasIssueContaining('Argon2 threads', $result);
    }

    public function test_argon2_threads_issue_has_low_severity(): void
    {
        $config = <<<'PHP'
<?php

return [
    'argon' => [
        'threads' => 1,
    ],
];
PHP;

        $tempDir = $this->createTempDirectory(['config/hashing.php' => $config]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(Severity::Low, $issues[0]->severity);
    }

    // ==================== Weak Driver Tests ====================

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

    public function test_detects_sha1_driver(): void
    {
        $config = <<<'PHP'
<?php

return [
    'driver' => 'sha1',
];
PHP;

        $tempDir = $this->createTempDirectory(['config/hashing.php' => $config]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('sha1', $result);
    }

    public function test_detects_sha256_driver(): void
    {
        $config = <<<'PHP'
<?php

return [
    'driver' => 'sha256',
];
PHP;

        $tempDir = $this->createTempDirectory(['config/hashing.php' => $config]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('sha256', $result);
    }

    // ==================== Weak Hashing in Code Tests ====================

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

    public function test_detects_sha1_hashing_in_code(): void
    {
        $code = <<<'PHP'
<?php

class UserController
{
    public function update($request)
    {
        $password = sha1($request->password);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('sha1', $result);
    }

    public function test_detects_pos_t_password_hashing(): void
    {
        $code = <<<'PHP'
<?php

class Controller
{
    public function store()
    {
        $hash = md5($_POST['password']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Controller.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Weak hashing function', $result);
    }

    public function test_ignores_md5_in_comments(): void
    {
        $code = <<<'PHP'
<?php

class UserService
{
    // Don't use md5($password) - it's insecure
    public function hashPassword($password)
    {
        return bcrypt($password);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_md5_for_cache_keys(): void
    {
        $code = <<<'PHP'
<?php

class CacheService
{
    public function getCacheKey($password, $email)
    {
        return md5($password . '_cache_' . $email);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/CacheService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_md5_for_fingerprints(): void
    {
        $code = <<<'PHP'
<?php

class FingerprintService
{
    public function generateFingerprint($data)
    {
        return md5($data . '_fingerprint');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/FingerprintService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ==================== password_hash() Tests ====================

    public function test_detects_password_hash_with_md5(): void
    {
        $code = <<<'PHP'
<?php

class AuthService
{
    public function hash($password)
    {
        return password_hash($password, PASSWORD_MD5);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/AuthService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('PASSWORD_MD5', $result);
    }

    public function test_detects_password_hash_with_sha1(): void
    {
        $code = <<<'PHP'
<?php

class PasswordService
{
    public function hashPassword($pwd)
    {
        return password_hash($pwd, PASSWORD_SHA1);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/PasswordService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('PASSWORD_SHA1', $result);
    }

    public function test_detects_password_hash_with_sha256(): void
    {
        $code = <<<'PHP'
<?php

class HashService
{
    public function create($password)
    {
        return password_hash($password, PASSWORD_SHA256);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/HashService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('PASSWORD_SHA256', $result);
    }

    // ==================== Plain-Text Password Tests ====================

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

    public function test_detects_pos_t_password_storage(): void
    {
        $code = <<<'PHP'
<?php

class Controller
{
    public function create()
    {
        $user->password = $_POST['password'];
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Controller.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('plain-text password', $result);
    }

    public function test_ignores_password_comparison(): void
    {
        $code = <<<'PHP'
<?php

class AuthService
{
    public function verify($user, $request)
    {
        if ($user->password === $request->password) {
            return true;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/AuthService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_hashed_password_assignment(): void
    {
        $code = <<<'PHP'
<?php

class UserService
{
    public function create($data)
    {
        $user->password = $hashedPassword;
        $user->save();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_password_with_hash_make(): void
    {
        $code = <<<'PHP'
<?php

class Controller
{
    public function store($request)
    {
        $user->password = Hash::make($request->password);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Controller.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_password_with_bcrypt(): void
    {
        $code = <<<'PHP'
<?php

class UserController
{
    public function create($request)
    {
        $user->password = bcrypt($request->password);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ==================== Multiple Issues Tests ====================

    public function test_handles_multiple_issues_in_single_config(): void
    {
        $config = <<<'PHP'
<?php

return [
    'driver' => 'md5',
    'bcrypt' => [
        'rounds' => 8,
    ],
    'argon' => [
        'memory' => 1024,
        'time' => 1,
    ],
];
PHP;

        $tempDir = $this->createTempDirectory(['config/hashing.php' => $config]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThan(1, count($issues));
    }

    // ==================== Edge Cases Tests ====================

    public function test_handles_single_quote_syntax(): void
    {
        $config = <<<'PHP'
<?php

return [
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

    public function test_handles_double_quote_syntax(): void
    {
        $config = <<<'PHP'
<?php

return [
    "bcrypt" => [
        "rounds" => 10,
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

    public function test_skips_vendor_files(): void
    {
        $code = <<<'PHP'
<?php

namespace Vendor\Package;

class SomeClass
{
    public function hash($password)
    {
        return md5($password);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'vendor/package/src/SomeClass.php' => $code,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['vendor']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_test_files(): void
    {
        $code = <<<'PHP'
<?php

namespace Tests\Feature;

class AuthTest
{
    public function test_password_hashing()
    {
        $hash = md5($password);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'tests/Feature/AuthTest.php' => $code,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['tests']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ==================== Result Format Tests ====================

    public function test_result_uses_result_by_severity(): void
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

        // Result should be instance of ResultInterface
        $this->assertInstanceOf(\ShieldCI\AnalyzersCore\Contracts\ResultInterface::class, $result);

        // Should have getMessage() method (from resultBySeverity)
        $this->assertIsString($result->getMessage());
    }

    public function test_summary_message_format_singular(): void
    {
        $config = <<<'PHP'
<?php

return [
    'bcrypt' => [
        'rounds' => 10,
    ],
];
PHP;

        $tempDir = $this->createTempDirectory(['config/hashing.php' => $config]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertStringContainsString('1 password hashing security issue', $result->getMessage());
    }

    public function test_summary_message_format_plural(): void
    {
        $config = <<<'PHP'
<?php

return [
    'driver' => 'md5',
    'bcrypt' => [
        'rounds' => 8,
    ],
];
PHP;

        $tempDir = $this->createTempDirectory(['config/hashing.php' => $config]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertStringContainsString('password hashing security issues', $result->getMessage());
    }
}
