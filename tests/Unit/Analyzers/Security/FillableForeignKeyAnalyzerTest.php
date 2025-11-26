<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\FillableForeignKeyAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class FillableForeignKeyAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new FillableForeignKeyAnalyzer($this->parser);
    }

    // ==================== Basic Detection Tests ====================

    public function test_passes_with_no_foreign_keys_in_fillable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    protected $fillable = ['title', 'content', 'published_at'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Post.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_foreign_key_in_fillable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Comment extends Model
{
    protected $fillable = ['content', 'post_id'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Comment.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('post_id', $result);
    }

    // ==================== Dangerous Pattern Tests ====================

    public function test_detects_critical_user_id_in_fillable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    protected $fillable = ['title', 'content', 'user_id'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Post.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('user_id', $result);
        $this->assertHasIssueContaining('impersonate', $result);

        $issues = $result->getIssues();
        $this->assertEquals(Severity::Critical, $issues[0]->severity);
    }

    public function test_detects_owner_id_in_fillable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Document extends Model
{
    protected $fillable = ['title', 'owner_id'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Document.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('owner_id', $result);

        $issues = $result->getIssues();
        $this->assertEquals(Severity::Critical, $issues[0]->severity);
    }

    public function test_detects_author_id_in_fillable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Article extends Model
{
    protected $fillable = ['title', 'author_id'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Article.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('author_id', $result);

        $issues = $result->getIssues();
        $this->assertEquals(Severity::Critical, $issues[0]->severity);
    }

    public function test_detects_creator_id_in_fillable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Task extends Model
{
    protected $fillable = ['name', 'creator_id'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Task.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('creator_id', $result);

        $issues = $result->getIssues();
        $this->assertEquals(Severity::Critical, $issues[0]->severity);
    }

    public function test_detects_parent_id_in_fillable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Category extends Model
{
    protected $fillable = ['name', 'parent_id'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Category.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('parent_id', $result);

        $issues = $result->getIssues();
        $this->assertEquals(Severity::Critical, $issues[0]->severity);
    }

    public function test_detects_tenant_id_in_fillable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Data extends Model
{
    protected $fillable = ['value', 'tenant_id'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Data.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('tenant_id', $result);

        $issues = $result->getIssues();
        $this->assertEquals(Severity::Critical, $issues[0]->severity);
    }

    public function test_detects_organization_id_in_fillable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Project extends Model
{
    protected $fillable = ['name', 'organization_id'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Project.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('organization_id', $result);

        $issues = $result->getIssues();
        $this->assertEquals(Severity::Critical, $issues[0]->severity);
    }

    // ==================== Duplicate Issue Tests ====================

    public function test_does_not_create_duplicate_issues_for_dangerous_patterns(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    protected $fillable = ['title', 'user_id'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Post.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        // CRITICAL: Verify only ONE issue created (not two!)
        $this->assertCount(1, $result->getIssues());
        $this->assertEquals(Severity::Critical, $result->getIssues()[0]->severity);
    }

    // ==================== Multiple Foreign Keys Tests ====================

    public function test_detects_multiple_foreign_keys(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Comment extends Model
{
    protected $fillable = ['content', 'post_id', 'user_id', 'parent_id'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Comment.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        // Should detect: user_id (Critical), parent_id (Critical), post_id (High)
        $this->assertCount(3, $result->getIssues());
    }

    public function test_detects_mix_of_dangerous_and_normal_foreign_keys(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Review extends Model
{
    protected $fillable = ['content', 'rating', 'product_id', 'user_id'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Review.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertCount(2, $result->getIssues());

        // user_id should be Critical
        $criticalIssue = collect($result->getIssues())
            ->first(fn ($issue) => str_contains($issue->message, 'user_id'));
        $this->assertNotNull($criticalIssue);
        $this->assertEquals(Severity::Critical, $criticalIssue->severity);

        // product_id should be High
        $highIssue = collect($result->getIssues())
            ->first(fn ($issue) => str_contains($issue->message, 'product_id'));
        $this->assertNotNull($highIssue);
        $this->assertEquals(Severity::High, $highIssue->severity);
    }

    // ==================== Edge Cases ====================

    public function test_handles_empty_fillable_array(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected $fillable = [];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/User.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_model_without_fillable_property(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected $guarded = [];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/User.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_only_checks_eloquent_models(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DataService
{
    protected $fillable = ['user_id', 'post_id'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DataService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Non-Eloquent classes are now skipped due to shouldRun()
        $this->assertSkipped($result);
    }

    public function test_handles_class_without_extends(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

class SimpleClass
{
    protected $fillable = ['user_id'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/SimpleClass.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Classes without extends are now skipped due to shouldRun()
        $this->assertSkipped($result);
    }

    // ==================== Model Inheritance Tests ====================

    public function test_detects_model_with_full_namespace(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends \Illuminate\Database\Eloquent\Model
{
    protected $fillable = ['title', 'user_id'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Post.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('user_id', $result);
    }

    public function test_detects_authenticatable_model(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    protected $fillable = ['name', 'email', 'tenant_id'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/User.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('tenant_id', $result);
    }

    public function test_detects_pivot_model(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Relations\Pivot;

class RoleUser extends Pivot
{
    protected $fillable = ['role_id', 'user_id'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/RoleUser.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        // Both are critical dangerous patterns
        $this->assertCount(2, $result->getIssues());
    }

    // ==================== shouldRun() Tests ====================

    public function test_should_run_when_models_exist(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    protected $fillable = ['title'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Post.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_should_not_run_when_no_models_exist(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DataService
{
    protected $fillable = ['user_id'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DataService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $this->assertFalse($analyzer->shouldRun());
    }

    public function test_get_skip_reason(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DataService
{
    public function getData() {}
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DataService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $reason = $analyzer->getSkipReason();
        $this->assertStringContainsString('No Eloquent models', $reason);
    }

    // ==================== Metadata Tests ====================

    public function test_metadata_includes_field_information(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Comment extends Model
{
    protected $fillable = ['content', 'post_id'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Comment.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];

        $this->assertArrayHasKey('field_name', $issue->metadata);
        $this->assertEquals('post_id', $issue->metadata['field_name']);
        $this->assertArrayHasKey('model_name', $issue->metadata);
        $this->assertEquals('Comment', $issue->metadata['model_name']);
        $this->assertArrayHasKey('is_dangerous_pattern', $issue->metadata);
        $this->assertFalse($issue->metadata['is_dangerous_pattern']);
        $this->assertArrayHasKey('pattern_type', $issue->metadata);
        $this->assertEquals('foreign_key', $issue->metadata['pattern_type']);
    }

    public function test_metadata_includes_dangerous_pattern_info(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    protected $fillable = ['title', 'user_id'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Post.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];

        $this->assertArrayHasKey('field_name', $issue->metadata);
        $this->assertEquals('user_id', $issue->metadata['field_name']);
        $this->assertArrayHasKey('is_dangerous_pattern', $issue->metadata);
        $this->assertTrue($issue->metadata['is_dangerous_pattern']);
        $this->assertArrayHasKey('pattern_type', $issue->metadata);
        $this->assertEquals('user ownership', $issue->metadata['pattern_type']);
    }

    // ==================== Message Format Tests ====================

    public function test_high_severity_message_format(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Comment extends Model
{
    protected $fillable = ['post_id'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Comment.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];
        $this->assertStringContainsString('Potential foreign key', $issue->message);
        $this->assertStringContainsString('post_id', $issue->message);
        $this->assertStringContainsString('Comment', $issue->message);
    }

    public function test_critical_severity_message_format(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    protected $fillable = ['user_id'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Post.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $issue = $result->getIssues()[0];
        $this->assertStringContainsString('Critical', $issue->message);
        $this->assertStringContainsString('user_id', $issue->message);
        $this->assertStringContainsString('impersonate', $issue->message);
    }

    // ==================== Analyzer Metadata Test ====================

    public function test_analyzer_runs_successfully(): void
    {
        // Test that analyzer runs without errors on valid code
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    protected $fillable = ['title', 'content'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Post.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Verify analyzer runs successfully
        $this->assertPassed($result);
    }
}
