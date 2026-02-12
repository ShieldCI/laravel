<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\PasswordSecurityAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class PasswordSecurityAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new PasswordSecurityAnalyzer($this->parser);
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

    public function test_should_run_returns_true_when_php_files_exist_even_without_hashing_config(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/User.php' => '<?php class User {}',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

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
        $bcryptIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'Bcrypt rounds')) {
                $bcryptIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($bcryptIssue);
        $this->assertEquals(Severity::Critical, $bcryptIssue->severity);
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
        $bcryptIssue = null;
        foreach ($issues as $issue) {
            if (isset($issue->metadata['rounds'])) {
                $bcryptIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($bcryptIssue);
        $this->assertEquals(8, $bcryptIssue->metadata['rounds']);
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
        $memoryIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'Argon2 memory')) {
                $memoryIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($memoryIssue);
        $this->assertEquals(Severity::Critical, $memoryIssue->severity);
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
        $timeIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'Argon2 time cost')) {
                $timeIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($timeIssue);
        $this->assertEquals(Severity::Medium, $timeIssue->severity);
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
        $threadIssue = null;
        foreach ($issues as $issue) {
            if (str_contains($issue->message, 'Argon2 threads')) {
                $threadIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($threadIssue);
        $this->assertEquals(Severity::Low, $threadIssue->severity);
    }

    // ==================== Argon Config Driver Gating Tests ====================

    public function test_does_not_flag_argon_params_when_driver_is_bcrypt(): void
    {
        $config = <<<'PHP'
<?php

return [
    'driver' => 'bcrypt',
    'bcrypt' => [
        'rounds' => 12,
    ],
    'argon' => [
        'memory' => 512,
        'time' => 1,
        'threads' => 1,
    ],
];
PHP;

        $tempDir = $this->createTempDirectory(['config/hashing.php' => $config]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $hasArgonIssue = false;
        foreach ($result->getIssues() as $issue) {
            if (str_contains($issue->message, 'Argon2')) {
                $hasArgonIssue = true;
                break;
            }
        }
        $this->assertFalse($hasArgonIssue, 'Should not flag argon params when driver is bcrypt');
    }

    public function test_flags_argon_when_no_driver_specified(): void
    {
        $config = <<<'PHP'
<?php

return [
    'argon' => [
        'memory' => 512,
        'time' => 1,
        'threads' => 1,
    ],
];
PHP;

        $tempDir = $this->createTempDirectory(['config/hashing.php' => $config]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('Argon2 memory', $result);
        $this->assertHasIssueContaining('Argon2 time cost', $result);
        $this->assertHasIssueContaining('Argon2 threads', $result);
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

    public function test_detects_plain_text_password_storage(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function store($request)
    {
        $password = $request->password;
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

    public function test_ignores_password_with_hash_make(): void
    {
        $code = <<<'PHP'
<?php

class Controller
{
    public function store($request)
    {
        $password = Hash::make($request->password);
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

    public function test_skips_vendor_files(): void
    {
        $code = <<<'PHP'
<?php

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

    // ==================== AST-based Weak Hash Detection Tests ====================

    public function test_detects_md5_on_credentials_array_password(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function login($request)
    {
        $hash = md5($credentials['password']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('Weak hashing function md5()', $result);
    }

    public function test_detects_md5_on_request_input_password(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function login($request)
    {
        $hash = md5($request->input('password'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('Weak hashing function md5()', $result);
    }

    public function test_detects_sha1_on_request_password_coalesce(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function login($request)
    {
        $hash = sha1($request->password ?? '');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('Weak hashing function sha1()', $result);
    }

    public function test_detects_plain_text_data_array_password(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function store($request)
    {
        $data['password'] = $request->input('password');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('plain-text password', $result);
    }

    public function test_detects_plain_text_property_password_storage(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $user = new \App\Models\User();
        $user->password = $request->password;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('plain-text password', $result);
    }

    public function test_ignores_property_password_with_hash_make(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $user = new \App\Models\User();
        $user->password = Hash::make($request->password);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasPlainTextIssue = false;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'plain_text_password') {
                $hasPlainTextIssue = true;
                break;
            }
        }
        $this->assertFalse($hasPlainTextIssue, 'Should not flag $user->password when using Hash::make()');
    }

    public function test_ignores_password_assignment_with_bcrypt(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function store($request)
    {
        $password = bcrypt($request->password);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasPlainTextIssue = false;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'plain_text_password') {
                $hasPlainTextIssue = true;
                break;
            }
        }
        $this->assertFalse($hasPlainTextIssue, 'Should not flag password assignment when using bcrypt()');
    }

    public function test_ignores_password_assignment_with_hash_driver_make(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Hash;

class AuthController
{
    public function store($request)
    {
        $user->password = Hash::driver('argon2id')->make($request->password);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasPlainTextIssue = false;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'plain_text_password') {
                $hasPlainTextIssue = true;
                break;
            }
        }
        $this->assertFalse($hasPlainTextIssue, 'Should not flag $user->password when using Hash::driver()->make()');
    }

    public function test_ignores_password_stored_via_hasher_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Hash;

class AuthController
{
    public function store($request)
    {
        $hasher = Hash::driver('argon2id');
        $user->password = $hasher->make($request->password);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasPlainTextIssue = false;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'plain_text_password') {
                $hasPlainTextIssue = true;
                break;
            }
        }
        $this->assertFalse($hasPlainTextIssue, 'Should not flag $user->password when using Hash::driver() variable with ->make()');
    }

    public function test_detects_plain_password_without_hasher_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Hash;

class AuthController
{
    public function store($request)
    {
        $hasher = Hash::driver('argon2id');
        $user->password = $request->password;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasPlainTextIssue = false;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'plain_text_password') {
                $hasPlainTextIssue = true;
                break;
            }
        }
        $this->assertTrue($hasPlainTextIssue, 'Should flag $user->password when raw password is assigned even though a hasher variable exists');
    }

    // ==================== Result Format Tests ====================

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

        $this->assertStringContainsString('1 password security issue', $result->getMessage());
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

        $this->assertStringContainsString('password security issues', $result->getMessage());
    }

    // ==================== Password Policy Tests ====================

    public function test_detects_missing_password_defaults(): void
    {
        $providerCode = <<<'PHP'
<?php

namespace App\Providers;

class AppServiceProvider
{
    public function boot()
    {
        // nothing configured
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/AppServiceProvider.php' => $providerCode,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('No Password::defaults()', $result);
    }

    public function test_passes_with_complete_password_defaults(): void
    {
        $providerCode = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Validation\Rules\Password;

class AppServiceProvider
{
    public function boot()
    {
        Password::defaults(function () {
            return Password::min(8)
                ->letters()
                ->mixedCase()
                ->numbers()
                ->symbols()
                ->uncompromised();
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/AppServiceProvider.php' => $providerCode,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_missing_uncompromised_check(): void
    {
        $providerCode = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Validation\Rules\Password;

class AppServiceProvider
{
    public function boot()
    {
        Password::defaults(function () {
            return Password::min(8)->mixedCase();
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/AppServiceProvider.php' => $providerCode,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('breached password', $result);
    }

    public function test_detects_missing_mixed_case(): void
    {
        $providerCode = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Validation\Rules\Password;

class AppServiceProvider
{
    public function boot()
    {
        Password::defaults(function () {
            return Password::min(8)->uncompromised();
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/AppServiceProvider.php' => $providerCode,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('mixed case', $result);
    }

    public function test_detects_weak_password_validation_in_request(): void
    {
        $requestCode = <<<'PHP'
<?php

namespace App\Http\Requests;

class RegisterRequest
{
    public function rules()
    {
        return [
            'email' => 'required|email',
            'password' => 'required|min:4|confirmed',
        ];
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Requests/RegisterRequest.php' => $requestCode,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('Password validation requires only 4 characters', $result);
    }

    public function test_detects_weak_password_validation_in_controller(): void
    {
        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $request->validate([
            'password' => 'required|min:6|confirmed',
        ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/AuthController.php' => $controllerCode,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('Password validation requires only 6 characters', $result);
    }

    // ==================== AST-based Validation Rules Tests ====================

    public function test_detects_weak_password_in_array_rules(): void
    {
        $requestCode = <<<'PHP'
<?php

namespace App\Http\Requests;

class RegisterRequest
{
    public function rules()
    {
        return [
            'password' => ['required', 'min:4', 'confirmed'],
        ];
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Requests/RegisterRequest.php' => $requestCode,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('Password validation requires only 4 characters', $result);
    }

    public function test_detects_weak_password_min_via_password_rule_object(): void
    {
        $requestCode = <<<'PHP'
<?php

namespace App\Http\Requests;

use Illuminate\Validation\Rules\Password;

class RegisterRequest
{
    public function rules()
    {
        return [
            'password' => Password::min(4)->letters(),
        ];
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Requests/RegisterRequest.php' => $requestCode,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('Password validation requires only 4 characters', $result);
    }

    public function test_passes_strong_password_rule_object(): void
    {
        $requestCode = <<<'PHP'
<?php

namespace App\Http\Requests;

use Illuminate\Validation\Rules\Password;

class RegisterRequest
{
    public function rules()
    {
        return [
            'password' => Password::min(8)->mixedCase(),
        ];
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Requests/RegisterRequest.php' => $requestCode,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasWeakValidation = false;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'weak_validation_min_length') {
                $hasWeakValidation = true;
                break;
            }
        }
        $this->assertFalse($hasWeakValidation, 'Password::min(8) should not trigger weak validation issue');
    }

    // ==================== Timeout Tests ====================

    public function test_detects_long_password_confirmation_timeout(): void
    {
        $authConfig = <<<'PHP'
<?php

return [
    'defaults' => [
        'guard' => 'web',
    ],
    'password_timeout' => 14400,
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/auth.php' => $authConfig,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('Password confirmation timeout', $result);
    }

    public function test_passes_with_short_password_confirmation_timeout(): void
    {
        $authConfig = <<<'PHP'
<?php

return [
    'password_timeout' => 3600,
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/auth.php' => $authConfig,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $hasTimeoutIssue = false;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'long_password_confirmation_timeout') {
                $hasTimeoutIssue = true;
                break;
            }
        }
        $this->assertFalse($hasTimeoutIssue);
    }

    public function test_timeout_issue_includes_human_readable_duration(): void
    {
        $authConfig = <<<'PHP'
<?php

return [
    'password_timeout' => 14400,
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/auth.php' => $authConfig,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('4h', $result);
    }

    public function test_does_not_flag_laravel_default_timeout(): void
    {
        $authConfig = <<<'PHP'
<?php

return [
    'password_timeout' => 10800,
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/auth.php' => $authConfig,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $hasTimeoutIssue = false;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'long_password_confirmation_timeout') {
                $hasTimeoutIssue = true;
                break;
            }
        }
        $this->assertFalse($hasTimeoutIssue, 'Should not flag Laravel default timeout of 10800 (3h)');
    }

    public function test_timeout_threshold_is_configurable(): void
    {
        $authConfig = <<<'PHP'
<?php

return [
    'password_timeout' => 7200,
];
PHP;

        $tempDir = $this->createTempDirectory([
            'config/auth.php' => $authConfig,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->app['config']->set('shieldci.password_security.password_confirmation_max_timeout', 3600);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('Password confirmation timeout', $result);
    }

    // ==================== Password::defaults() AST Tests ====================

    public function test_detects_password_defaults_with_arrow_function(): void
    {
        $providerCode = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Validation\Rules\Password;

class AppServiceProvider
{
    public function boot()
    {
        Password::defaults(fn () => Password::min(8)->mixedCase()->uncompromised());
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/AppServiceProvider.php' => $providerCode,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ==================== False Positive Regression Tests ====================

    public function test_fp1_ignores_md5_on_password_prefixed_variables(): void
    {
        $code = <<<'PHP'
<?php

class AuthService
{
    public function resetToken($passwordResetToken)
    {
        return md5($passwordResetToken);
    }

    public function fieldHash($passwordField)
    {
        return sha1($passwordField);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/AuthService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasWeakHashIssue = false;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'weak_hash_function') {
                $hasWeakHashIssue = true;
                break;
            }
        }
        $this->assertFalse($hasWeakHashIssue, 'Should not flag md5/sha1 on $passwordResetToken or $passwordField');
    }

    public function test_fp1_still_detects_md5_on_exact_password_variable(): void
    {
        $code = <<<'PHP'
<?php

class AuthController
{
    public function register($request)
    {
        $hash = md5($password);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('Weak hashing function', $result);
    }

    public function test_fp2_detects_eloquent_property_password_assignment(): void
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

        $this->assertHasIssueContaining('plain-text password', $result);
    }

    public function test_fp3_detects_password_defaults_in_bootstrap_app(): void
    {
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Validation\Rules\Password;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting()
    ->booting(function () {
        Password::defaults(function () {
            return Password::min(8)
                ->mixedCase()
                ->uncompromised();
        });
    })
    ->create();
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrapApp,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $hasMissingDefaults = false;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'missing_password_defaults') {
                $hasMissingDefaults = true;
                break;
            }
        }
        $this->assertFalse($hasMissingDefaults, 'Should detect Password::defaults() in bootstrap/app.php');
    }

    public function test_fp3_detects_password_defaults_in_custom_provider(): void
    {
        $providerCode = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Validation\Rules\Password;

class SecurityServiceProvider
{
    public function boot()
    {
        Password::defaults(function () {
            return Password::min(10)->mixedCase()->uncompromised();
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/SecurityServiceProvider.php' => $providerCode,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasMissingDefaults = false;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'missing_password_defaults') {
                $hasMissingDefaults = true;
                break;
            }
        }
        $this->assertFalse($hasMissingDefaults, 'Should detect Password::defaults() in custom provider');
    }

    public function test_fp4_ignores_weak_hash_in_block_comment(): void
    {
        $code = <<<'PHP'
<?php

class SecureController
{
    public function hash($password)
    {
        $result = /* md5($password) */ Hash::make($password);
        return $result;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/SecureController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasWeakHashIssue = false;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'weak_hash_function') {
                $hasWeakHashIssue = true;
                break;
            }
        }
        $this->assertFalse($hasWeakHashIssue, 'Should not flag md5() inside block comments');
    }

    public function test_fp6_password_min_outside_defaults_does_not_affect_check(): void
    {
        $providerCode = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Validation\Rules\Password;

class AppServiceProvider
{
    public function boot()
    {
        Password::defaults(function () {
            return Password::min(12)->mixedCase()->uncompromised();
        });
    }

    public function someValidation()
    {
        return Password::min(4);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/AppServiceProvider.php' => $providerCode,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasMinLengthIssue = false;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'weak_password_min_length') {
                $hasMinLengthIssue = true;
                break;
            }
        }
        $this->assertFalse($hasMinLengthIssue, 'Password::min(4) outside defaults should not override min(12) inside defaults');
    }

    public function test_fp7_ignores_seeders_and_factories(): void
    {
        $seederCode = <<<'PHP'
<?php

class UserSeeder
{
    public function run()
    {
        $hash = md5($password);
    }
}
PHP;

        $factoryCode = <<<'PHP'
<?php

class UserFactory
{
    public function definition()
    {
        $hash = md5($password);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'database/seeders/UserSeeder.php' => $seederCode,
            'database/factories/UserFactory.php' => $factoryCode,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['database']);

        $result = $analyzer->analyze();

        $hasWeakHashIssue = false;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'weak_hash_function') {
                $hasWeakHashIssue = true;
                break;
            }
        }
        $this->assertFalse($hasWeakHashIssue, 'Should not scan database/seeders/ or database/factories/');
    }

    // ==================== password_hash() Algorithm Tests ====================

    public function test_detects_password_hash_with_integer_literal_algorithm(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = password_hash($password, 0);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('potentially weak or unknown algorithm', $result);
    }

    public function test_detects_password_hash_with_variable_algorithm(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = password_hash($password, $algo);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('potentially weak or unknown algorithm', $result);
    }

    public function test_detects_password_hash_with_unknown_constant(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = password_hash($password, PASSWORD_MD5);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('potentially weak or unknown algorithm', $result);
    }

    public function test_passes_password_hash_with_password_default(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = password_hash($password, PASSWORD_DEFAULT);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasWeakAlgoIssue = false;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'weak_password_hash_algorithm') {
                $hasWeakAlgoIssue = true;
                break;
            }
        }
        $this->assertFalse($hasWeakAlgoIssue, 'PASSWORD_DEFAULT should be considered safe');
    }

    public function test_passes_password_hash_with_password_bcrypt(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = password_hash($password, PASSWORD_BCRYPT);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasWeakAlgoIssue = false;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'weak_password_hash_algorithm') {
                $hasWeakAlgoIssue = true;
                break;
            }
        }
        $this->assertFalse($hasWeakAlgoIssue, 'PASSWORD_BCRYPT should be considered safe');
    }

    public function test_passes_password_hash_with_argon2id(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = password_hash($password, PASSWORD_ARGON2ID);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasWeakAlgoIssue = false;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'weak_password_hash_algorithm') {
                $hasWeakAlgoIssue = true;
                break;
            }
        }
        $this->assertFalse($hasWeakAlgoIssue, 'PASSWORD_ARGON2ID should be considered safe');
    }

    public function test_passes_password_hash_with_no_second_argument(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = password_hash($password);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasWeakAlgoIssue = false;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'weak_password_hash_algorithm') {
                $hasWeakAlgoIssue = true;
                break;
            }
        }
        $this->assertFalse($hasWeakAlgoIssue, 'password_hash() with no second arg defaults to PASSWORD_DEFAULT which is safe');
    }

    public function test_ignores_password_hash_on_non_password_argument(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = password_hash($token, 0);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasWeakAlgoIssue = false;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'weak_password_hash_algorithm') {
                $hasWeakAlgoIssue = true;
                break;
            }
        }
        $this->assertFalse($hasWeakAlgoIssue, 'Should not flag password_hash() when first arg is not password-related');
    }

    public function test_password_hash_weak_algorithm_has_critical_severity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = password_hash($password, $algo);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $algoIssue = null;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'weak_password_hash_algorithm') {
                $algoIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($algoIssue);
        $this->assertEquals(Severity::Critical, $algoIssue->severity);
    }

    // ==================== password_hash() Options Validation Tests ====================

    public function test_detects_password_hash_with_weak_bcrypt_cost(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 4]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('bcrypt cost (4)', $result);
    }

    public function test_passes_password_hash_with_strong_bcrypt_cost(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasCostIssue = false;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'weak_password_hash_bcrypt_cost') {
                $hasCostIssue = true;
                break;
            }
        }
        $this->assertFalse($hasCostIssue, 'cost=12 should not trigger weak bcrypt cost issue');
    }

    public function test_detects_password_default_with_explicit_options(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = password_hash($password, PASSWORD_DEFAULT, ['cost' => 8]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('PASSWORD_DEFAULT', $result);

        // Verify it's an info-level issue, not a bcrypt cost issue
        $defaultIssue = null;
        foreach ($result->getIssues() as $issue) {
            if (str_contains($issue->message, 'PASSWORD_DEFAULT')) {
                $defaultIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($defaultIssue);
        $this->assertSame(Severity::Info, $defaultIssue->severity);
        $this->assertSame('password_default_with_options', $defaultIssue->metadata['issue_type']);

        // Ensure no bcrypt cost issue is emitted (the key behavioral change)
        foreach ($result->getIssues() as $issue) {
            $this->assertStringNotContainsString('bcrypt cost', $issue->message);
        }
    }

    public function test_detects_password_hash_argon2id_with_weak_memory_cost(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = password_hash($password, PASSWORD_ARGON2ID, ['memory_cost' => 1024]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('argon2 memory_cost (1024 KB)', $result);
    }

    public function test_detects_password_hash_argon2id_with_weak_time_cost(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = password_hash($password, PASSWORD_ARGON2ID, ['time_cost' => 1]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $timeIssue = null;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'weak_password_hash_argon2_time') {
                $timeIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($timeIssue);
        $this->assertEquals(Severity::Medium, $timeIssue->severity);
    }

    public function test_passes_password_hash_argon2id_with_strong_options(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = password_hash($password, PASSWORD_ARGON2ID, ['memory_cost' => 65536, 'time_cost' => 2, 'threads' => 2]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasArgonOptionIssue = false;
        foreach ($result->getIssues() as $issue) {
            $type = $issue->metadata['issue_type'] ?? '';
            if (in_array($type, ['weak_password_hash_argon2_memory', 'weak_password_hash_argon2_time', 'weak_password_hash_argon2_threads'], true)) {
                $hasArgonOptionIssue = true;
                break;
            }
        }
        $this->assertFalse($hasArgonOptionIssue, 'Strong argon2 options should not trigger any issues');
    }

    public function test_ignores_password_hash_options_with_variable_cost(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => $cost]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasCostIssue = false;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'weak_password_hash_bcrypt_cost') {
                $hasCostIssue = true;
                break;
            }
        }
        $this->assertFalse($hasCostIssue, 'Variable cost should be skipped (cannot evaluate at static analysis time)');
    }

    public function test_password_hash_bcrypt_cost_severity_is_critical(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 4]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $costIssue = null;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'weak_password_hash_bcrypt_cost') {
                $costIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($costIssue);
        $this->assertEquals(Severity::Critical, $costIssue->severity);
    }

    // ==================== Unknown password_hash Options Key Tests ====================

    public function test_detects_unknown_keys_in_bcrypt_options(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12, 'foo' => 123]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $unknownIssue = null;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'unknown_password_hash_options') {
                $unknownIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($unknownIssue, 'Should detect unknown key "foo" in bcrypt options');
        $this->assertEquals(Severity::Info, $unknownIssue->severity);
        $this->assertEquals(['foo'], $unknownIssue->metadata['unknown_keys']);
        $this->assertStringContainsString('foo', $unknownIssue->message);
    }

    public function test_detects_unknown_keys_in_argon2id_options(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = password_hash($password, PASSWORD_ARGON2ID, ['memory_cost' => 65536, 'unknown_opt' => 99]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $unknownIssue = null;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'unknown_password_hash_options') {
                $unknownIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($unknownIssue, 'Should detect unknown key "unknown_opt" in argon2id options');
        $this->assertEquals(Severity::Info, $unknownIssue->severity);
        $this->assertEquals(['unknown_opt'], $unknownIssue->metadata['unknown_keys']);
    }

    public function test_no_warning_for_valid_bcrypt_options(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $unknownKeyIssues = array_filter(
            $result->getIssues(),
            fn ($issue) => ($issue->metadata['issue_type'] ?? null) === 'unknown_password_hash_options'
        );
        $this->assertEmpty($unknownKeyIssues, 'Valid bcrypt options should not trigger unknown key warning');
    }

    public function test_no_warning_for_valid_argon2id_options(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = password_hash($password, PASSWORD_ARGON2ID, ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 2]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $unknownKeyIssues = array_filter(
            $result->getIssues(),
            fn ($issue) => ($issue->metadata['issue_type'] ?? null) === 'unknown_password_hash_options'
        );
        $this->assertEmpty($unknownKeyIssues, 'Valid argon2id options should not trigger unknown key warning');
    }

    public function test_detects_bcrypt_key_as_unknown_in_argon_options(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = password_hash($password, PASSWORD_ARGON2ID, ['memory_cost' => 65536, 'cost' => 12]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $unknownIssue = null;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'unknown_password_hash_options') {
                $unknownIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($unknownIssue, 'Bcrypt "cost" key should be flagged as unknown for ARGON2ID');
        $this->assertEquals(['cost'], $unknownIssue->metadata['unknown_keys']);
    }

    public function test_detects_unknown_keys_with_non_integer_values(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12, 'salt' => 'mysalt']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $unknownIssue = null;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'unknown_password_hash_options') {
                $unknownIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($unknownIssue, 'String-valued "salt" key should be detected as unknown even though value-validation skips non-integers');
        $this->assertEquals(['salt'], $unknownIssue->metadata['unknown_keys']);
    }

    // ==================== Password::defaults() Per-Call AND-Reduction Tests ====================

    public function test_detects_weak_defaults_masked_by_strong_provider(): void
    {
        $strongProvider = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Validation\Rules\Password;

class AppServiceProvider
{
    public function boot()
    {
        Password::defaults(function () {
            return Password::min(8)->mixedCase()->uncompromised();
        });
    }
}
PHP;

        $weakProvider = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Validation\Rules\Password;

class AuthServiceProvider
{
    public function boot()
    {
        Password::defaults(function () {
            return Password::min(8);
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/AppServiceProvider.php' => $strongProvider,
            'app/Providers/AuthServiceProvider.php' => $weakProvider,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('mixed case', $result);
        $this->assertHasIssueContaining('breached password', $result);
    }

    public function test_passes_when_all_defaults_calls_are_strong(): void
    {
        $providerA = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Validation\Rules\Password;

class AppServiceProvider
{
    public function boot()
    {
        Password::defaults(function () {
            return Password::min(8)->mixedCase()->uncompromised();
        });
    }
}
PHP;

        $providerB = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Validation\Rules\Password;

class AuthServiceProvider
{
    public function boot()
    {
        Password::defaults(function () {
            return Password::min(10)->mixedCase()->uncompromised();
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/AppServiceProvider.php' => $providerA,
            'app/Providers/AuthServiceProvider.php' => $providerB,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_two_defaults_in_same_file_one_weak(): void
    {
        $providerCode = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Validation\Rules\Password;

class AppServiceProvider
{
    public function boot()
    {
        Password::defaults(function () {
            return Password::min(8)->mixedCase()->uncompromised();
        });

        Password::defaults(function () {
            return Password::min(8);
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/AppServiceProvider.php' => $providerCode,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('mixed case', $result);
        $this->assertHasIssueContaining('breached password', $result);
    }

    public function test_weak_defaults_in_bootstrap_masked_by_provider(): void
    {
        $weakBootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Validation\Rules\Password;

return Application::configure(basePath: dirname(__DIR__))
    ->booting(function () {
        Password::defaults(function () {
            return Password::min(8);
        });
    })
    ->create();
PHP;

        $strongProvider = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Validation\Rules\Password;

class AppServiceProvider
{
    public function boot()
    {
        Password::defaults(function () {
            return Password::min(8)->mixedCase()->uncompromised();
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $weakBootstrap,
            'app/Providers/AppServiceProvider.php' => $strongProvider,
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('mixed case', $result);
        $this->assertHasIssueContaining('breached password', $result);
    }

    // ==================== Password Rehash Detection Tests ====================

    public function test_passes_rehash_when_rehash_on_login_is_true(): void
    {
        $hashingConfig = <<<'PHP'
<?php

return [
    'driver' => 'bcrypt',
    'bcrypt' => ['rounds' => 12],
    'rehash_on_login' => true,
];
PHP;

        $loginController = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;

class LoginController
{
    public function login($request)
    {
        Auth::attempt($request->only('email', 'password'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/hashing.php' => $hashingConfig,
            'app/Http/Controllers/LoginController.php' => $loginController,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasRehashIssue = false;
        foreach ($result->getIssues() as $issue) {
            $type = $issue->metadata['issue_type'] ?? '';
            if (in_array($type, ['rehash_on_login_disabled', 'missing_password_rehash'], true)) {
                $hasRehashIssue = true;
                break;
            }
        }
        $this->assertFalse($hasRehashIssue, 'rehash_on_login=true should not trigger rehash issues');
    }

    public function test_detects_rehash_on_login_disabled(): void
    {
        $hashingConfig = <<<'PHP'
<?php

return [
    'driver' => 'bcrypt',
    'bcrypt' => ['rounds' => 12],
    'rehash_on_login' => false,
];
PHP;

        $loginController = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;

class LoginController
{
    public function login($request)
    {
        Auth::attempt($request->only('email', 'password'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/hashing.php' => $hashingConfig,
            'app/Http/Controllers/LoginController.php' => $loginController,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('rehash_on_login is false', $result);
    }

    public function test_no_rehash_issue_when_rehash_on_login_false_but_no_auth(): void
    {
        $hashingConfig = <<<'PHP'
<?php

return [
    'driver' => 'bcrypt',
    'bcrypt' => ['rounds' => 12],
    'rehash_on_login' => false,
];
PHP;

        $serviceCode = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function doSomething()
    {
        return 'no auth here';
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/hashing.php' => $hashingConfig,
            'app/Services/UserService.php' => $serviceCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasRehashIssue = false;
        foreach ($result->getIssues() as $issue) {
            $type = $issue->metadata['issue_type'] ?? '';
            if (in_array($type, ['rehash_on_login_disabled', 'missing_password_rehash'], true)) {
                $hasRehashIssue = true;
                break;
            }
        }
        $this->assertFalse($hasRehashIssue, 'No auth code means no rehash issue should be flagged');
    }

    public function test_detects_missing_rehash_when_auth_attempt_exists(): void
    {
        $hashingConfig = <<<'PHP'
<?php

return [
    'driver' => 'bcrypt',
    'bcrypt' => ['rounds' => 12],
];
PHP;

        $loginController = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;

class LoginController
{
    public function login($request)
    {
        Auth::attempt($request->only('email', 'password'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/hashing.php' => $hashingConfig,
            'app/Http/Controllers/LoginController.php' => $loginController,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('never rehashes passwords', $result);
    }

    public function test_passes_when_hash_needs_rehash_is_present(): void
    {
        $hashingConfig = <<<'PHP'
<?php

return [
    'driver' => 'bcrypt',
    'bcrypt' => ['rounds' => 12],
];
PHP;

        $loginController = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class LoginController
{
    public function login($request)
    {
        if (Auth::attempt($request->only('email', 'password'))) {
            if (Hash::needsRehash($request->user()->password)) {
                $request->user()->update(['password' => Hash::make($request->password)]);
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/hashing.php' => $hashingConfig,
            'app/Http/Controllers/LoginController.php' => $loginController,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasRehashIssue = false;
        foreach ($result->getIssues() as $issue) {
            $type = $issue->metadata['issue_type'] ?? '';
            if (in_array($type, ['rehash_on_login_disabled', 'missing_password_rehash'], true)) {
                $hasRehashIssue = true;
                break;
            }
        }
        $this->assertFalse($hasRehashIssue, 'Hash::needsRehash() present should not trigger rehash issue');
    }

    public function test_passes_when_password_needs_rehash_is_present(): void
    {
        $hashingConfig = <<<'PHP'
<?php

return [
    'driver' => 'bcrypt',
    'bcrypt' => ['rounds' => 12],
];
PHP;

        $loginController = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;

class LoginController
{
    public function login($request)
    {
        if (Auth::attempt($request->only('email', 'password'))) {
            if (password_needs_rehash($request->user()->password, PASSWORD_DEFAULT)) {
                $request->user()->update(['password' => password_hash($request->password, PASSWORD_DEFAULT)]);
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/hashing.php' => $hashingConfig,
            'app/Http/Controllers/LoginController.php' => $loginController,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasRehashIssue = false;
        foreach ($result->getIssues() as $issue) {
            $type = $issue->metadata['issue_type'] ?? '';
            if (in_array($type, ['rehash_on_login_disabled', 'missing_password_rehash'], true)) {
                $hasRehashIssue = true;
                break;
            }
        }
        $this->assertFalse($hasRehashIssue, 'password_needs_rehash() present should not trigger rehash issue');
    }

    public function test_no_rehash_issue_when_no_auth_attempt(): void
    {
        $hashingConfig = <<<'PHP'
<?php

return [
    'driver' => 'bcrypt',
    'bcrypt' => ['rounds' => 12],
];
PHP;

        $apiController = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ApiController
{
    public function index()
    {
        return response()->json(['status' => 'ok']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/hashing.php' => $hashingConfig,
            'app/Http/Controllers/ApiController.php' => $apiController,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasRehashIssue = false;
        foreach ($result->getIssues() as $issue) {
            $type = $issue->metadata['issue_type'] ?? '';
            if (in_array($type, ['rehash_on_login_disabled', 'missing_password_rehash'], true)) {
                $hasRehashIssue = true;
                break;
            }
        }
        $this->assertFalse($hasRehashIssue, 'No Auth::attempt() means no rehash issue');
    }

    public function test_detects_missing_rehash_with_auth_helper_attempt(): void
    {
        $hashingConfig = <<<'PHP'
<?php

return [
    'driver' => 'bcrypt',
    'bcrypt' => ['rounds' => 12],
];
PHP;

        $loginController = <<<'PHP'
<?php

namespace App\Http\Controllers;

class LoginController
{
    public function login($request)
    {
        auth()->attempt($request->only('email', 'password'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/hashing.php' => $hashingConfig,
            'app/Http/Controllers/LoginController.php' => $loginController,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('never rehashes passwords', $result);
    }

    public function test_detects_missing_rehash_with_auth_login(): void
    {
        $hashingConfig = <<<'PHP'
<?php

return [
    'driver' => 'bcrypt',
    'bcrypt' => ['rounds' => 12],
];
PHP;

        $loginController = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;

class LoginController
{
    public function login($user)
    {
        Auth::login($user);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/hashing.php' => $hashingConfig,
            'app/Http/Controllers/LoginController.php' => $loginController,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('never rehashes passwords', $result);
    }

    public function test_detects_missing_rehash_with_auth_login_using_id(): void
    {
        $hashingConfig = <<<'PHP'
<?php

return [
    'driver' => 'bcrypt',
    'bcrypt' => ['rounds' => 12],
];
PHP;

        $loginController = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;

class LoginController
{
    public function login($id)
    {
        Auth::loginUsingId($id);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/hashing.php' => $hashingConfig,
            'app/Http/Controllers/LoginController.php' => $loginController,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('never rehashes passwords', $result);
    }

    public function test_detects_missing_rehash_with_auth_helper_login(): void
    {
        $hashingConfig = <<<'PHP'
<?php

return [
    'driver' => 'bcrypt',
    'bcrypt' => ['rounds' => 12],
];
PHP;

        $loginController = <<<'PHP'
<?php

namespace App\Http\Controllers;

class LoginController
{
    public function login($user)
    {
        auth()->login($user);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/hashing.php' => $hashingConfig,
            'app/Http/Controllers/LoginController.php' => $loginController,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('never rehashes passwords', $result);
    }

    public function test_detects_missing_rehash_with_fortify_authenticate_using(): void
    {
        $hashingConfig = <<<'PHP'
<?php

return [
    'driver' => 'bcrypt',
    'bcrypt' => ['rounds' => 12],
];
PHP;

        $fortifyProvider = <<<'PHP'
<?php

namespace App\Providers;

use Laravel\Fortify\Fortify;

class FortifyServiceProvider
{
    public function boot()
    {
        Fortify::authenticateUsing(function ($request) {
            return null;
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/hashing.php' => $hashingConfig,
            'app/Providers/FortifyServiceProvider.php' => $fortifyProvider,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('never rehashes passwords', $result);
    }

    public function test_passes_when_auth_login_with_hash_needs_rehash(): void
    {
        $hashingConfig = <<<'PHP'
<?php

return [
    'driver' => 'bcrypt',
    'bcrypt' => ['rounds' => 12],
];
PHP;

        $loginController = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class LoginController
{
    public function login($user)
    {
        Auth::login($user);
        if (Hash::needsRehash($user->password)) {
            $user->update(['password' => Hash::make('secret')]);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/hashing.php' => $hashingConfig,
            'app/Http/Controllers/LoginController.php' => $loginController,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasRehashIssue = false;
        foreach ($result->getIssues() as $issue) {
            $type = $issue->metadata['issue_type'] ?? '';
            if (in_array($type, ['rehash_on_login_disabled', 'missing_password_rehash'], true)) {
                $hasRehashIssue = true;
                break;
            }
        }
        $this->assertFalse($hasRehashIssue, 'Auth::login() with Hash::needsRehash() should not trigger rehash issue');
    }

    public function test_passes_when_hasher_variable_needs_rehash(): void
    {
        $hashingConfig = <<<'PHP'
<?php

return [
    'driver' => 'bcrypt',
    'bcrypt' => ['rounds' => 12],
];
PHP;

        $loginController = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;

class LoginController
{
    public function login($request, $hasher)
    {
        if (Auth::attempt($request->only('email', 'password'))) {
            if ($hasher->needsRehash($request->user()->password)) {
                $request->user()->update(['password' => $hasher->make($request->password)]);
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/hashing.php' => $hashingConfig,
            'app/Http/Controllers/LoginController.php' => $loginController,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasRehashIssue = false;
        foreach ($result->getIssues() as $issue) {
            $type = $issue->metadata['issue_type'] ?? '';
            if (in_array($type, ['rehash_on_login_disabled', 'missing_password_rehash'], true)) {
                $hasRehashIssue = true;
                break;
            }
        }
        $this->assertFalse($hasRehashIssue, '$hasher->needsRehash() should be recognized as a valid rehash call');
    }

    public function test_ignores_needs_rehash_on_non_hash_variable(): void
    {
        $hashingConfig = <<<'PHP'
<?php

return [
    'driver' => 'bcrypt',
    'bcrypt' => ['rounds' => 12],
];
PHP;

        $loginController = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;

class LoginController
{
    public function login($request, $cache)
    {
        if (Auth::attempt($request->only('email', 'password'))) {
            if ($cache->needsRehash($request->user()->password)) {
                $request->user()->update(['password' => 'rehashed']);
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/hashing.php' => $hashingConfig,
            'app/Http/Controllers/LoginController.php' => $loginController,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('never rehashes passwords', $result);
    }

    // ==================== Validated Array Password Detection (Bug 1 Verification) ====================

    public function test_detects_validated_array_password_as_plaintext(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function store($request)
    {
        $data['password'] = $request->validated()['password'];
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('plain-text password', $result);
    }

    // ==================== hash() Function Weak Algorithm Detection (Bug 3) ====================

    public function test_detects_hash_sha256_for_password(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = hash('sha256', $request->password);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hashIssue = null;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'weak_hash_function'
                && isset($issue->metadata['algorithm']) && $issue->metadata['algorithm'] === 'sha256') {
                $hashIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($hashIssue, "Should detect hash('sha256', \$request->password) as weak hashing");
        $this->assertEquals(Severity::Critical, $hashIssue->severity);
        $this->assertEquals('hash', $hashIssue->metadata['function']);
    }

    public function test_detects_hash_md5_for_password(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = hash('md5', $password);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hashIssue = null;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'weak_hash_function'
                && isset($issue->metadata['algorithm']) && $issue->metadata['algorithm'] === 'md5') {
                $hashIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($hashIssue, "Should detect hash('md5', \$password) as weak hashing");
        $this->assertEquals(Severity::Critical, $hashIssue->severity);
        $this->assertEquals('hash', $hashIssue->metadata['function']);
    }

    public function test_ignores_hash_with_non_password_argument(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $hash = hash('sha256', $someData);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasWeakHashIssue = false;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'weak_hash_function') {
                $hasWeakHashIssue = true;
                break;
            }
        }
        $this->assertFalse($hasWeakHashIssue, 'Should not flag hash() when second argument is not password-related');
    }

    // ==================== Hashed Value Wrapping Tests ====================

    public function test_ignores_password_with_trim_wrapping_hash_make(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Hash;

class UserController
{
    public function store($request)
    {
        $user->password = trim(Hash::make($request->password));
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertNoPlainTextPasswordIssue($result);
    }

    public function test_ignores_password_with_strtolower_wrapping_hash_make(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Hash;

class UserController
{
    public function store($request)
    {
        $user->password = strtolower(Hash::make($request->password));
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertNoPlainTextPasswordIssue($result);
    }

    public function test_ignores_password_with_string_cast_wrapping_hash_make(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Hash;

class UserController
{
    public function store($request)
    {
        $user->password = (string) Hash::make($request->password);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertNoPlainTextPasswordIssue($result);
    }

    public function test_ignores_password_with_nested_wrapping_hash_make(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Hash;

class UserController
{
    public function store($request)
    {
        $user->password = strtolower(trim(Hash::make($request->password)));
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertNoPlainTextPasswordIssue($result);
    }

    public function test_ignores_password_with_cast_wrapping_bcrypt(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function store($request)
    {
        $user->password = (string) bcrypt($request->password);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertNoPlainTextPasswordIssue($result);
    }

    public function test_ignores_password_with_ternary_containing_hash(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Hash;

class UserController
{
    public function store($request, $condition)
    {
        $user->password = $condition ? Hash::make($request->password) : '';
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertNoPlainTextPasswordIssue($result);
    }

    public function test_still_detects_plaintext_with_trim_wrapping_raw_password(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function store($request)
    {
        $user->password = trim($request->password);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasPlainTextPasswordIssue($result);
    }

    // ==================== Method Call Plaintext Detection Tests ====================

    public function test_detects_plaintext_password_in_model_create(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController
{
    public function store($request)
    {
        User::create([
            'name' => $request->name,
            'password' => $request->password,
        ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasPlainTextPasswordIssue($result);
    }

    public function test_detects_plaintext_password_in_db_insert(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\DB;

class UserController
{
    public function store($request)
    {
        DB::table('users')->insert([
            'name' => $request->name,
            'password' => $request->password,
        ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasPlainTextPasswordIssue($result);
    }

    public function test_detects_plaintext_password_in_model_update(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function update($user, $request)
    {
        $user->update([
            'password' => $request->password,
        ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasPlainTextPasswordIssue($result);
    }

    public function test_detects_plaintext_password_in_model_fill(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function update($user, $data)
    {
        $user->fill([
            'password' => $data['password'],
        ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasPlainTextPasswordIssue($result);
    }

    public function test_detects_plaintext_password_in_force_create(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController
{
    public function store($input)
    {
        User::forceCreate([
            'password' => $input->password,
        ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasPlainTextPasswordIssue($result);
    }

    public function test_detects_plaintext_password_in_update_or_create(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController
{
    public function store($request)
    {
        User::updateOrCreate(
            ['email' => $request->email],
            ['password' => $request->password],
        );
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasPlainTextPasswordIssue($result);
    }

    public function test_ignores_hashed_password_in_model_create(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Support\Facades\Hash;

class UserController
{
    public function store($request)
    {
        User::create([
            'name' => $request->name,
            'password' => Hash::make($request->password),
        ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertNoPlainTextPasswordIssue($result);
    }

    public function test_ignores_hashed_password_in_model_update(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function update($user, $request)
    {
        $user->update([
            'password' => bcrypt($request->password),
        ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertNoPlainTextPasswordIssue($result);
    }

    public function test_ignores_wrapped_hash_in_model_create(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Support\Facades\Hash;

class UserController
{
    public function store($request)
    {
        User::create([
            'name' => $request->name,
            'password' => trim(Hash::make($request->password)),
        ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertNoPlainTextPasswordIssue($result);
    }

    public function test_ignores_create_without_password_key(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController
{
    public function store($request)
    {
        User::create([
            'name' => $request->name,
            'email' => $request->email,
        ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertNoPlainTextPasswordIssue($result);
    }

    // ==================== Additional Request Method Tests ====================

    public function test_detects_weak_hash_of_request_post_password(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $password = md5($request->post('password'));
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

    public function test_detects_weak_hash_of_request_query_password(): void
    {
        $code = <<<'PHP'
<?php

class AuthController
{
    public function register($request)
    {
        $password = sha1($request->query('password'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/AuthController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('sha1', $result);
    }

    public function test_detects_weak_hash_of_request_json_password(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AuthController
{
    public function register($request)
    {
        $password = md5($request->json('password'));
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

    public function test_detects_plaintext_password_via_request_post(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function store($user, $request)
    {
        $user->update([
            'password' => $request->post('password'),
        ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasPlainTextPasswordIssue($result);
    }

    public function test_detects_plaintext_password_in_create_via_request_json(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController
{
    public function store($request)
    {
        User::create([
            'name' => $request->name,
            'password' => $request->json('password'),
        ]);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasPlainTextPasswordIssue($result);
    }

    // ==================== Rehash Heuristic Tightening Tests ====================

    public function test_does_not_count_hashmap_needs_rehash_as_valid(): void
    {
        $hashingConfig = <<<'PHP'
<?php

return [
    'driver' => 'bcrypt',
    'bcrypt' => ['rounds' => 12],
];
PHP;

        $loginController = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;

class LoginController
{
    public function login($request, $hashmap)
    {
        if (Auth::attempt($request->only('email', 'password'))) {
            if ($hashmap->needsRehash($request->user()->password)) {
                $request->user()->update(['password' => 'rehashed']);
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/hashing.php' => $hashingConfig,
            'app/Http/Controllers/LoginController.php' => $loginController,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('never rehashes passwords', $result);
    }

    public function test_hasher_variable_needs_rehash_is_valid(): void
    {
        $hashingConfig = <<<'PHP'
<?php

return [
    'driver' => 'bcrypt',
    'bcrypt' => ['rounds' => 12],
];
PHP;

        $loginController = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;

class LoginController
{
    public function login($request, $hasher)
    {
        if (Auth::attempt($request->only('email', 'password'))) {
            if ($hasher->needsRehash($request->user()->password)) {
                $request->user()->update(['password' => $hasher->make($request->password)]);
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/hashing.php' => $hashingConfig,
            'app/Http/Controllers/LoginController.php' => $loginController,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasRehashIssue = false;
        foreach ($result->getIssues() as $issue) {
            $type = $issue->metadata['issue_type'] ?? '';
            if (in_array($type, ['rehash_on_login_disabled', 'missing_password_rehash'], true)) {
                $hasRehashIssue = true;
                break;
            }
        }
        $this->assertFalse($hasRehashIssue, '$hasher->needsRehash() should be recognized as a valid rehash call');
    }

    public function test_hash_manager_variable_needs_rehash_is_valid(): void
    {
        $hashingConfig = <<<'PHP'
<?php

return [
    'driver' => 'bcrypt',
    'bcrypt' => ['rounds' => 12],
];
PHP;

        $loginController = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;

class LoginController
{
    public function login($request, $hashManager)
    {
        if (Auth::attempt($request->only('email', 'password'))) {
            if ($hashManager->needsRehash($request->user()->password)) {
                $request->user()->update(['password' => $hashManager->make($request->password)]);
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'config/hashing.php' => $hashingConfig,
            'app/Http/Controllers/LoginController.php' => $loginController,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $hasRehashIssue = false;
        foreach ($result->getIssues() as $issue) {
            $type = $issue->metadata['issue_type'] ?? '';
            if (in_array($type, ['rehash_on_login_disabled', 'missing_password_rehash'], true)) {
                $hasRehashIssue = true;
                break;
            }
        }
        $this->assertFalse($hasRehashIssue, '$hashManager->needsRehash() should be recognized as a valid rehash call');
    }

    // ==================== Indirect Variable Assignment Tests ====================

    public function test_detects_plaintext_password_via_variable_in_model_create(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController
{
    public function store($request)
    {
        $data = [
            'name' => $request->name,
            'password' => $request->password,
        ];
        User::create($data);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasPlainTextPasswordIssue($result);
    }

    public function test_detects_plaintext_password_via_variable_in_db_insert(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\DB;

class UserController
{
    public function store($request)
    {
        $data = [
            'name' => $request->name,
            'password' => $request->input('password'),
        ];
        DB::table('users')->insert($data);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasPlainTextPasswordIssue($result);
    }

    public function test_ignores_hashed_password_via_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Support\Facades\Hash;

class UserController
{
    public function store($request)
    {
        $data = [
            'name' => $request->name,
            'password' => Hash::make($request->password),
        ];
        User::create($data);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertNoPlainTextPasswordIssue($result);
    }

    public function test_ignores_variable_without_password_key(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController
{
    public function store($request)
    {
        $data = [
            'name' => $request->name,
            'email' => $request->email,
        ];
        User::create($data);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertNoPlainTextPasswordIssue($result);
    }

    public function test_detects_plaintext_via_variable_in_update_or_create(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController
{
    public function store($request)
    {
        $values = ['password' => $request->password];
        User::updateOrCreate(
            ['email' => $request->email],
            $values,
        );
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasPlainTextPasswordIssue($result);
    }

    public function test_detects_incremental_array_password_in_create(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController
{
    public function store($request)
    {
        $data = [];
        $data['name'] = $request->name;
        $data['password'] = $request->password;
        User::create($data);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasPlainTextPasswordIssue($result);
    }

    public function test_ignores_incremental_array_with_hashed_password(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Support\Facades\Hash;

class UserController
{
    public function store($request)
    {
        $data = [];
        $data['name'] = $request->name;
        $data['password'] = Hash::make($request->password);
        User::create($data);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertNoPlainTextPasswordIssue($result);
    }

    public function test_detects_incremental_array_password_in_insert(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\DB;

class UserController
{
    public function store($request)
    {
        $data['name'] = $request->name;
        $data['password'] = $request->input('password');
        DB::table('users')->insert($data);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Http/Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertHasPlainTextPasswordIssue($result);
    }

    // ==================== CI Compatibility Tests ====================

    public function test_not_run_in_ci(): void
    {
        $this->assertFalse(PasswordSecurityAnalyzer::$runInCI);
    }

    public function test_metadata_has_correct_id(): void
    {
        $analyzer = $this->createAnalyzer();
        $tempDir = $this->createTempDirectory([
            'config/hashing.php' => '<?php return ["driver" => "bcrypt", "bcrypt" => ["rounds" => 12]];',
        ]);
        $analyzer->setBasePath($tempDir);

        $result = $analyzer->analyze();

        $this->assertEquals('password-security', $result->getAnalyzerId());
    }

    // ==================== Helper Assertions ====================

    private function assertNoPlainTextPasswordIssue(\ShieldCI\AnalyzersCore\Contracts\ResultInterface $result): void
    {
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'plain_text_password') {
                $this->fail('Expected no plain-text password issue, but one was found: '.$issue->message);
            }
        }

        $this->addToAssertionCount(1);
    }

    private function assertHasPlainTextPasswordIssue(\ShieldCI\AnalyzersCore\Contracts\ResultInterface $result): void
    {
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'plain_text_password') {
                $this->addToAssertionCount(1);

                return;
            }
        }

        $this->fail('Expected a plain-text password issue, but none was found');
    }
}
