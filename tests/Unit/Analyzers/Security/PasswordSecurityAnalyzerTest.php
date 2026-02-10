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

    public function test_fp2_ignores_eloquent_property_password_assignment(): void
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

        $hasPlainTextIssue = false;
        foreach ($result->getIssues() as $issue) {
            if (isset($issue->metadata['issue_type']) && $issue->metadata['issue_type'] === 'plain_text_password') {
                $hasPlainTextIssue = true;
                break;
            }
        }
        $this->assertFalse($hasPlainTextIssue, 'Should not flag Eloquent model property assignment (mutators/casts)');
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
}
