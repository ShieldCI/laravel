<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Analyzers\CodeQuality\TodoCommentAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\Tests\AnalyzerTestCase;

class TodoCommentAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new TodoCommentAnalyzer;
    }

    #[Test]
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

    #[Test]
    public function test_detects_fixme_comments(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class PaymentService
{
    public function process()
    {
        // FIXME: This validation is broken
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/PaymentService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('FIXME', $result);
    }

    #[Test]
    public function test_detects_hack_comments(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class OrderService
{
    public function calculate()
    {
        // HACK: Temporary workaround for timezone issue
        return date('Y-m-d');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/OrderService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('HACK', $result);
    }

    #[Test]
    public function test_detects_xxx_comments(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class SecurityService
{
    public function validate()
    {
        // XXX: This needs review before production
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/SecurityService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('XXX', $result);
    }

    #[Test]
    public function test_detects_bug_comments(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class DataService
{
    public function fetch()
    {
        // BUG: Race condition in concurrent access
        return $this->data;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/DataService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('BUG', $result);
    }

    #[Test]
    public function test_detects_case_insensitive_keywords(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class TestService
{
    public function run()
    {
        // todo: lowercase
        // Todo: mixed case
        // TODO: uppercase
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/TestService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertCount(3, $issues);
    }

    #[Test]
    public function test_detects_todo_with_colon(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class UserService
{
    public function create()
    {
        // TODO: implement validation
        return [];
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

        $this->assertWarning($result);
        $this->assertHasIssueContaining('TODO', $result);
    }

    #[Test]
    public function test_detects_todo_with_at_symbol(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class MailService
{
    public function send()
    {
        // @TODO implement retry logic
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/MailService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('TODO', $result);
    }

    #[Test]
    public function test_detects_comments_in_block_comments(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class ApiService
{
    public function request()
    {
        /*
         * TODO: Add authentication
         * FIXME: Handle rate limiting
         */
        return $this->client->get('/api');
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/ApiService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(2, count($issues));
    }

    #[Test]
    public function test_detects_multiple_keywords_on_same_line(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class CacheService
{
    public function clear()
    {
        // TODO: FIXME: This needs refactoring
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/CacheService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(2, count($issues));
    }

    #[Test]
    public function test_assigns_correct_severity_for_todo(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class Service
{
    public function run()
    {
        // TODO: implement this
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals(Severity::Low, $issues[0]->severity);
    }

    #[Test]
    public function test_assigns_correct_severity_for_fixme(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class Service
{
    public function run()
    {
        // FIXME: broken logic
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals(Severity::Medium, $issues[0]->severity);
    }

    #[Test]
    public function test_assigns_correct_severity_for_hack(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class Service
{
    public function run()
    {
        // HACK: temporary workaround
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $this->assertEquals(Severity::High, $issues[0]->severity);
    }

    #[Test]
    public function test_generates_summary_with_counts(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class MultiService
{
    public function process()
    {
        // TODO: Add validation
        // TODO: Add logging
        // FIXME: Fix bug
        // HACK: Temporary fix
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/MultiService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $message = $result->getMessage();
        $this->assertStringContainsString('2 TODO', $message);
        $this->assertStringContainsString('1 FIXME', $message);
        $this->assertStringContainsString('1 HACK', $message);
    }

    #[Test]
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

    #[Test]
    public function test_includes_correct_metadata(): void
    {
        $code = <<<'PHP'
<?php

namespace App;

class TestService
{
    public function run()
    {
        // TODO: implement feature
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/TestService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);

        $issue = $issues[0];
        $metadata = $issue->metadata;

        $this->assertArrayHasKey('keyword', $metadata);
        $this->assertArrayHasKey('comment', $metadata);
        $this->assertArrayHasKey('type', $metadata);
        $this->assertEquals('TODO', $metadata['keyword']);
        $this->assertIsString($metadata['comment']);
        $this->assertStringContainsString('implement feature', (string) $metadata['comment']);
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
        $this->assertEquals('todo-comment', $metadata->id);
        $this->assertEquals('Todo Comment Analyzer', $metadata->name);
        $this->assertStringContainsString('TODO', $metadata->description);
    }

    #[Test]
    public function test_detects_multiple_files_with_todos(): void
    {
        $code1 = <<<'PHP'
<?php

namespace App;

class Service1
{
    public function run()
    {
        // TODO: implement this
        return true;
    }
}
PHP;

        $code2 = <<<'PHP'
<?php

namespace App;

class Service2
{
    public function execute()
    {
        // FIXME: broken logic
        return false;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Service1.php' => $code1,
            'app/Service2.php' => $code2,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);

        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(2, count($issues));
    }
}
