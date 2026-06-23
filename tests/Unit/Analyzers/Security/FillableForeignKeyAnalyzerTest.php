<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use Illuminate\Config\Repository;
use ShieldCI\Analyzers\Security\FillableForeignKeyAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class FillableForeignKeyAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $config
     */
    protected function createAnalyzer(array $config = []): AnalyzerInterface
    {
        // Default dangerous patterns (same as in analyzer)
        $defaultPatterns = [
            'user_id' => 'user ownership',
            'author_id' => 'author relationship',
            'owner_id' => 'owner relationship',
            'creator_id' => 'creator relationship',
            'parent_id' => 'hierarchical relationship',
            'tenant_id' => 'tenant isolation',
            'organization_id' => 'organization ownership',
            'company_id' => 'company ownership',
            'team_id' => 'team membership',
            'account_id' => 'account ownership',
        ];

        // Get custom dangerous patterns from config if provided
        $customPatterns = $config['fillable-foreign-key']['dangerous_patterns'] ?? [];
        $dangerousPatterns = is_array($customPatterns) && ! empty($customPatterns)
            ? array_merge($defaultPatterns, $customPatterns)
            : $defaultPatterns;

        // Build security config
        $securityConfig = [
            'enabled' => true,
            'fillable-foreign-key' => [
                'dangerous_patterns' => $dangerousPatterns,
            ],
        ];

        // Remove fillable-foreign-key from config to avoid conflicts
        unset($config['fillable-foreign-key']);

        // Merge any remaining config
        if (! empty($config)) {
            $securityConfig = array_merge_recursive($securityConfig, $config);
        }

        $configRepo = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'security' => $securityConfig,
                ],
            ],
        ]);

        return new FillableForeignKeyAnalyzer($this->parser, $configRepo);
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

    public function test_generic_foreign_key_is_not_flagged(): void
    {
        // A generic *_id key (not a curated ownership/impersonation pattern) is no
        // longer reported: fillable-FK exploitability is a data-flow concern handled
        // by MassAssignmentAnalyzer, not a lexical field-name check.
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

        $this->assertPassed($result);
        $this->assertIssueCount(0, $result);
    }

    public function test_generic_foreign_keys_are_not_reported(): void
    {
        // Regression guard for the SIMS24 case: a model full of reference/catalog
        // foreign keys (none of them curated ownership/impersonation patterns) must
        // produce zero findings rather than a wall of high-severity false positives.
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Quotation extends Model
{
    protected $fillable = ['client_id', 'product_id', 'employee_id', 'deployment_id'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Quotation.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertIssueCount(0, $result);
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
        // Should detect: user_id (Critical), parent_id (Critical). post_id is a generic
        // foreign key and is no longer reported.
        $this->assertCount(2, $result->getIssues());
    }

    public function test_reports_only_dangerous_foreign_keys(): void
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
        // Only user_id (Critical) is reported; product_id is a generic foreign key.
        $this->assertCount(1, $result->getIssues());

        $criticalIssue = $result->getIssues()[0];
        $this->assertStringContainsString('user_id', $criticalIssue->message);
        $this->assertEquals(Severity::Critical, $criticalIssue->severity);
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

    public function test_empty_guarded_is_not_reported_here(): void
    {
        // $guarded = [] is a mass-assignment-protection concern owned by
        // MassAssignmentAnalyzer (which reports it Critical). This analyzer no longer
        // duplicates it, so a model whose only signal is $guarded = [] passes here.
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
        $this->assertIssueCount(0, $result);
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
        // user_id is a curated dangerous pattern (Critical); role_id is a generic
        // foreign key and is no longer reported.
        $this->assertCount(1, $result->getIssues());
        $this->assertEquals(Severity::Critical, $result->getIssues()[0]->severity);
        $this->assertHasIssueContaining('user_id', $result);
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
        $this->assertStringContainsString('user_id', $issue->message);
        $this->assertStringContainsString('impersonate', $issue->message);
    }

    // ==================== Line Number Tests ====================
    // Note: @shieldci-ignore suppression is applied by AnalyzeCommand, not the analyzer.
    // These tests verify that issues are reported at the array item line (not the property
    // declaration line), which is what allows per-item inline suppression to work correctly.

    public function test_dangerous_pattern_issue_is_reported_at_array_item_line(): void
    {
        // 'user_id' is on line 11, 'protected $fillable' is on line 9
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    protected $fillable = [
        'title',
        'user_id',
    ];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Post.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        // Issue must report at line 11 ('user_id'), not line 9 ('protected $fillable = [')
        $this->assertNotNull($issues[0]->location);
        $this->assertEquals(11, $issues[0]->location->line);
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

    public function test_passes_with_fillable_attribute_no_foreign_key(): void
    {
        // Direct regression for the Compass false positive: a #[Fillable] model with
        // no foreign keys must produce zero issues (no "inherited fillable" notice).
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;

#[Fillable(['first_name', 'last_name', 'phone', 'email', 'password'])]
class User extends Model
{
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/User.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertIssueCount(0, $result);
    }

    public function test_detects_company_id_in_fillable_attribute(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;

#[Fillable(['name', 'company_id'])]
class Membership extends Model
{
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Membership.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('company_id', $result);
    }

    public function test_detects_user_id_in_fillable_attribute_variadic(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;

#[Fillable('title', 'user_id')]
class Post extends Model
{
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
    }

    public function test_still_notices_when_no_property_and_no_attribute(): void
    {
        // True positive preserved: a model with neither $fillable property nor
        // #[Fillable] attribute still gets the medium "cannot analyze" notice.
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Widget extends Model
{
    protected $table = 'widgets';
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Widget.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $inheritedIssues = array_filter(
            $result->getIssues(),
            fn ($i) => isset($i->metadata['fillable_inherited']) && $i->metadata['fillable_inherited'] === true
        );
        $this->assertNotEmpty($inheritedIssues, 'Model with no fillable property or attribute should still get the notice');
    }
}
