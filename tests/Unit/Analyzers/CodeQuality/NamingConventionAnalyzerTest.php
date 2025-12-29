<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Analyzers\CodeQuality\NamingConventionAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class NamingConventionAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $config
     */
    protected function createAnalyzer(array $config = []): AnalyzerInterface
    {
        return new NamingConventionAnalyzer($this->parser);
    }

    #[Test]
    public function test_passes_when_all_names_follow_conventions(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Controllers;

class UserController
{
    private string $firstName;
    private int $totalAmount;
    public const MAX_RETRIES = 3;

    public function getUserById(int $id): void
    {
        // Valid code
    }

    public function processPayment(): void
    {
        // Valid code
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    #[Test]
    public function test_allows_single_character_properties_psr12_compliant(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

class Point
{
    private int $x;
    private int $y;
    private int $z;

    public function getX(): int
    {
        return $this->x;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Point.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    #[Test]
    public function test_flags_class_names_not_in_pascal_case(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Controllers;

class user_controller
{
    public function getUser(): void {}
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Controllers/user_controller.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertStringContainsString("Class 'user_controller' does not follow PascalCase convention", $issues[0]->message);
        $this->assertSame('UserController', $issues[0]->metadata['suggestion']);
    }

    #[Test]
    public function test_flags_interface_names_not_in_pascal_case(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Contracts;

interface user_repository
{
    public function find(int $id);
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
        $this->assertHasIssueContaining("Interface 'user_repository' does not follow PascalCase convention", $result);
    }

    #[Test]
    public function test_flags_trait_names_not_in_pascal_case(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Traits;

trait has_timestamps
{
    public function getCreatedAt() {}
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
        $this->assertHasIssueContaining("Trait 'has_timestamps' does not follow PascalCase convention", $result);
        $issues = $result->getIssues();
        $this->assertSame('HasTimestamps', $issues[0]->metadata['suggestion']);
    }

    #[Test]
    public function test_flags_enum_names_not_in_pascal_case(): void
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
        $this->assertHasIssueContaining("Enum 'user_status' does not follow PascalCase convention", $result);
    }

    #[Test]
    public function test_flags_method_names_not_in_camel_case(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function get_user_by_id(int $id): void {}

    public function ProcessPayment(): void {}
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
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
        $this->assertStringContainsString("Method 'get_user_by_id' does not follow camelCase convention", $issues[0]->message);
        $this->assertSame('getUserById', $issues[0]->metadata['suggestion']);
        $this->assertStringContainsString("Method 'ProcessPayment' does not follow camelCase convention", $issues[1]->message);
        $this->assertSame('processPayment', $issues[1]->metadata['suggestion']);
    }

    #[Test]
    public function test_skips_magic_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

class User
{
    public function __construct() {}
    public function __toString() {}
    public function __get($name) {}
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    #[Test]
    public function test_flags_property_names_not_in_camel_case(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

class User
{
    private string $first_name;
    private int $TotalAmount;
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
        $this->assertStringContainsString("Property 'first_name' does not follow camelCase convention", $issues[0]->message);
        $this->assertSame('firstName', $issues[0]->metadata['suggestion']);
        $this->assertStringContainsString("Property 'TotalAmount' does not follow camelCase convention", $issues[1]->message);
        $this->assertSame('totalAmount', $issues[1]->metadata['suggestion']);
    }

    #[Test]
    public function test_flags_public_constant_names_not_in_screaming_snake_case(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Config;

class Config
{
    public const maxRetries = 3;
    public const API_Key = 'secret';
    public const TimeoutSeconds = 30;
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Config/Config.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(3, $issues);
        $this->assertStringContainsString("Public constant 'maxRetries' does not follow SCREAMING_SNAKE_CASE convention", $issues[0]->message);
        $this->assertSame('MAX_RETRIES', $issues[0]->metadata['suggestion']);
    }

    #[Test]
    public function test_allows_acronyms_in_pascal_case(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Parsers;

class XMLParser {}
class HTTPClient {}
class APIController {}
interface JSONSerializable {}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Parsers/Acronyms.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    #[Test]
    public function test_provides_correct_recommendations_for_each_type(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class bad_class
{
    private string $Bad_Property;
    public const badConstant = 1;

    public function Bad_Method(): void {}
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/bad_class.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(4, $issues);

        // Check class recommendation
        $classIssue = collect($issues)->first(fn ($i) => $i->metadata['type'] === 'class');
        $this->assertNotNull($classIssue);
        $this->assertStringContainsString('Classes should use PascalCase', $classIssue->recommendation);
        $this->assertStringContainsString('BadClass', $classIssue->recommendation);

        // Check property recommendation
        $propertyIssue = collect($issues)->first(fn ($i) => $i->metadata['type'] === 'property');
        $this->assertNotNull($propertyIssue);
        $this->assertStringContainsString('Properties should use camelCase', $propertyIssue->recommendation);
        $this->assertStringContainsString('badProperty', $propertyIssue->recommendation);

        // Check constant recommendation
        $constantIssue = collect($issues)->first(fn ($i) => $i->metadata['type'] === 'constant');
        $this->assertNotNull($constantIssue);
        $this->assertStringContainsString('Public constants should use SCREAMING_SNAKE_CASE', $constantIssue->recommendation);
        $this->assertStringContainsString('BAD_CONSTANT', $constantIssue->recommendation);

        // Check method recommendation
        $methodIssue = collect($issues)->first(fn ($i) => $i->metadata['type'] === 'method');
        $this->assertNotNull($methodIssue);
        $this->assertStringContainsString('Methods should use camelCase', $methodIssue->recommendation);
        $this->assertStringContainsString('badMethod', $methodIssue->recommendation);
    }

    #[Test]
    public function test_handles_multiple_properties_in_one_statement(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

class User
{
    private string $first_name, $last_name, $email_address;
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/User.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(3, $issues);
        $this->assertStringContainsString("Property 'first_name' does not follow camelCase convention", $issues[0]->message);
        $this->assertStringContainsString("Property 'last_name' does not follow camelCase convention", $issues[1]->message);
        $this->assertStringContainsString("Property 'email_address' does not follow camelCase convention", $issues[2]->message);
    }

    #[Test]
    public function test_correctly_converts_snake_case_to_camel_case(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class Test
{
    private string $user_first_name;

    public function get_user_by_id(): void {}
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Test.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertSame('userFirstName', $issues[0]->metadata['suggestion']);
        $this->assertSame('getUserById', $issues[1]->metadata['suggestion']);
    }

    #[Test]
    public function test_correctly_converts_to_screaming_snake_case(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Config;

class Config
{
    public const maxRetryAttempts = 3;
    public const apiBaseUrl = 'https://api.example.com';
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Config/Config.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertSame('MAX_RETRY_ATTEMPTS', $issues[0]->metadata['suggestion']);
        $this->assertSame('API_BASE_URL', $issues[1]->metadata['suggestion']);
    }

    #[Test]
    public function test_allows_camel_case_for_private_and_protected_constants(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Config;

class Config
{
    // PSR-12: Only public constants require SCREAMING_SNAKE_CASE
    private const maxRetries = 3;
    protected const defaultTimeout = 30;
    private const apiBaseUrl = 'https://api.example.com';
    protected const cachePrefix = 'app_';

    // Public constants still require SCREAMING_SNAKE_CASE
    public const MAX_CONNECTIONS = 100;
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Config/Config.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - private/protected constants can use camelCase
        $this->assertPassed($result);
    }

    #[Test]
    public function test_flags_only_public_constants_with_incorrect_naming(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Config;

class Config
{
    // These should NOT be flagged (private/protected)
    private const maxRetries = 3;
    protected const defaultTimeout = 30;

    // These SHOULD be flagged (public with wrong naming)
    public const maxConnections = 100;
    public const apiKey = 'secret';
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Config/Config.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();

        // Only 2 issues for the public constants
        $this->assertCount(2, $issues);
        $this->assertStringContainsString("Public constant 'maxConnections'", $issues[0]->message);
        $this->assertSame('MAX_CONNECTIONS', $issues[0]->metadata['suggestion']);
        $this->assertStringContainsString("Public constant 'apiKey'", $issues[1]->message);
        $this->assertSame('API_KEY', $issues[1]->metadata['suggestion']);
    }
}
