<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Analyzers\CodeQuality\NamingConventionAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\Tests\AnalyzerTestCase;

class NamingConventionAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new NamingConventionAnalyzer($this->parser);
    }

    #[Test]
    public function test_detects_snake_case_class_names(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class user_service
{
    public function getUser()
    {
        return [];
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/user_service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('PascalCase', $result);
    }

    #[Test]
    public function test_detects_snake_case_method_names(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function Get_User($userId)
    {
        return [];
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
        $this->assertHasIssueContaining('camelCase', $result);
    }

    #[Test]
    public function test_detects_snake_case_property_names(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    private $User_Name;
    private $user_id;
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
        $this->assertHasIssueContaining('camelCase', $result);
    }

    #[Test]
    public function test_detects_camel_case_constant_names(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    private const maxRetries = 3;
    private const apiKey = 'secret';
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
        $this->assertHasIssueContaining('SCREAMING_SNAKE_CASE', $result);
    }

    #[Test]
    public function test_passes_with_psr_naming(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    private const MAX_RETRIES = 3;
    private const API_KEY = 'secret';

    private $userName;
    private $userId;

    public function getUser($userId)
    {
        return User::find($userId);
    }

    public function processPayment()
    {
        return true;
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

    #[Test]
    public function test_detects_single_letter_class_names(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class A
{
    public function test()
    {
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/A.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('PascalCase', $result);
    }

    #[Test]
    public function test_detects_single_letter_method_names(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class UserService
{
    public function a()
    {
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('camelCase', $result);
    }

    #[Test]
    public function test_detects_single_letter_property_names(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class UserService
{
    private $a;
    private $x;
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('camelCase', $result);
    }

    #[Test]
    public function test_detects_single_letter_constant_names(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class UserService
{
    private const A = 'test';
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('SCREAMING_SNAKE_CASE', $result);
    }

    #[Test]
    public function test_allows_acronyms_in_class_names(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class XMLParser
{
    public function parse()
    {
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/XMLParser.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    #[Test]
    public function test_allows_multiple_acronyms_in_class_names(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http;

class HTTPAPIClient
{
    public function request()
    {
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/HTTPAPIClient.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    #[Test]
    public function test_detects_interface_naming_violations(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Contracts;

interface user_repository
{
    public function find($id);
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Contracts/user_repository.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('PascalCase', $result);
    }

    #[Test]
    public function test_passes_with_correct_interface_naming(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Contracts;

interface UserRepositoryInterface
{
    public function find($id);
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Contracts/UserRepositoryInterface.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    #[Test]
    public function test_detects_trait_naming_violations(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Traits;

trait has_timestamps
{
    public function touch()
    {
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Traits/has_timestamps.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('PascalCase', $result);
    }

    #[Test]
    public function test_passes_with_correct_trait_naming(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Traits;

trait HasTimestamps
{
    public function touch()
    {
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Traits/HasTimestamps.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    #[Test]
    public function test_detects_enum_naming_violations(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Enums;

enum user_status
{
    case ACTIVE;
    case INACTIVE;
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Enums/user_status.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('PascalCase', $result);
    }

    #[Test]
    public function test_passes_with_correct_enum_naming(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Enums;

enum UserStatus
{
    case ACTIVE;
    case INACTIVE;
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Enums/UserStatus.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    #[Test]
    public function test_skips_magic_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class UserService
{
    public function __construct()
    {
    }

    public function __toString()
    {
        return '';
    }

    public function __get($name)
    {
        return null;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    #[Test]
    public function test_detects_multiple_violations_in_one_file(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class user_service
{
    private const maxRetries = 3;
    private $User_Name;

    public function Get_User($user_id)
    {
        return User::find($user_id);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/user_service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        // Should detect class, constant, property, and method violations
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(4, count($issues));
    }

    #[Test]
    public function test_handles_multiple_properties_on_one_line(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class UserService
{
    private $User_Name, $User_Email, $User_Age;
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        // Should detect all 3 property violations
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(3, count($issues));
    }

    #[Test]
    public function test_handles_multiple_constants_on_one_line(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class UserService
{
    private const maxRetries = 3, apiKey = 'secret', timeOut = 30;
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        // Should detect all 3 constant violations
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(3, count($issues));
    }

    #[Test]
    public function test_includes_correct_metadata(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class user_service
{
    public function test()
    {
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/user_service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $issue = $issues[0];
        $metadata = $issue->metadata;

        $this->assertArrayHasKey('type', $metadata);
        $this->assertArrayHasKey('name', $metadata);
        $this->assertArrayHasKey('suggestion', $metadata);
        $this->assertEquals('user_service', $metadata['name']);
        $this->assertEquals('UserService', $metadata['suggestion']);
    }

    #[Test]
    public function test_has_correct_analyzer_metadata(): void
    {
        $analyzer = $this->createAnalyzer();

        $reflection = new \ReflectionClass($analyzer);
        $method = $reflection->getMethod('metadata');
        $method->setAccessible(true);
        $metadata = $method->invoke($analyzer);

        $this->assertInstanceOf(AnalyzerMetadata::class, $metadata);
        $this->assertEquals('naming-convention', $metadata->id);
        $this->assertEquals('Naming Convention Analyzer', $metadata->name);
        $this->assertStringContainsString('PSR', $metadata->description);
    }

    #[Test]
    public function test_allows_numbers_in_names(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class User2Service
{
    private const MAX_RETRIES_V2 = 3;
    private $userId2;

    public function getUser2($userId)
    {
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/User2Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
