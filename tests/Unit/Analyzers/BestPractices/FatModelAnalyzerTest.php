<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use Illuminate\Config\Repository;
use ShieldCI\Analyzers\BestPractices\FatModelAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class FatModelAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $config
     */
    protected function createAnalyzer(array $config = []): AnalyzerInterface
    {
        $configRepo = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best_practices' => $config,
                ],
            ],
        ]);

        return new FatModelAnalyzer($this->parser, $configRepo);
    }

    public function test_passes_with_small_model(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected $fillable = ['name', 'email'];

    public function posts()
    {
        return $this->hasMany(Post::class);
    }

    public function getFullNameAttribute()
    {
        return $this->first_name . ' ' . $this->last_name;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/User.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_model_with_too_many_business_methods(): void
    {
        // Create a model with >15 business methods (threshold is 15)
        $methods = '';
        for ($i = 1; $i <= 20; $i++) {
            $methods .= "\n    public function businessMethod{$i}()\n    {\n        return 'value';\n    }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Product extends Model
{
    protected \$fillable = ['name', 'price'];
{$methods}
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Product.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('business methods', $result);
    }

    public function test_detects_model_with_too_many_lines(): void
    {
        // Create a model with >300 lines of actual code (properties + methods)
        // Each method has ~20 lines, so 16 methods = ~320 lines
        $methods = '';
        for ($i = 1; $i <= 16; $i++) {
            $methodBody = str_repeat("        \$value = 'line';\n", 20);
            $methods .= "\n    public function method{$i}()\n    {\n{$methodBody}        return 'value';\n    }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Order extends Model
{
    protected \$fillable = ['user_id', 'total'];
{$methods}
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Order.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('lines', $result);
    }

    public function test_provides_refactoring_recommendation(): void
    {
        $methods = '';
        for ($i = 1; $i <= 20; $i++) {
            $methods .= "\n    public function businessMethod{$i}() { return 'value'; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Invoice extends Model
{
{$methods}
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Invoice.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('service', $issues[0]->recommendation);
    }

    public function test_ignores_non_model_classes(): void
    {
        $methods = '';
        for ($i = 1; $i <= 20; $i++) {
            $methods .= "\n    public function method{$i}() { return 'value'; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Services;

class LargeService
{
{$methods}
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/LargeService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_files_with_parse_errors(): void
    {
        $code = '<?php this is invalid PHP code {{{';

        $tempDir = $this->createTempDirectory(['Invalid.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_scope_methods(): void
    {
        // Model with 18 scope methods - should all be excluded
        $scopes = '';
        for ($i = 1; $i <= 18; $i++) {
            $scopes .= "\n    public function scope{$i}(\$query)\n    {\n        return \$query->where('active', true);\n    }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
{$scopes}
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/User.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_old_style_accessors_and_mutators(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    public function getFullNameAttribute()
    {
        return $this->first_name . ' ' . $this->last_name;
    }

    public function setEmailAttribute($value)
    {
        $this->attributes['email'] = strtolower($value);
    }

    public function getAgeAttribute()
    {
        return now()->diffInYears($this->birth_date);
    }

    public function setPasswordAttribute($value)
    {
        $this->attributes['password'] = bcrypt($value);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/User.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_new_style_accessor_mutator_attributes(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected function nameAttribute(): Attribute
    {
        return Attribute::make(
            get: fn ($value) => ucfirst($value),
            set: fn ($value) => strtolower($value),
        );
    }

    protected function emailAttribute(): Attribute
    {
        return Attribute::make(
            get: fn ($value) => strtolower($value),
        );
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/User.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_single_line_relationships(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    public function user()
    {
        return $this->belongsTo(User::class);
    }

    public function comments()
    {
        return $this->hasMany(Comment::class);
    }

    public function tags()
    {
        return $this->belongsToMany(Tag::class);
    }

    public function category()
    {
        return $this->belongsTo(Category::class);
    }

    public function images()
    {
        return $this->morphMany(Image::class, 'imageable');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Post.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_multi_line_relationships(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    public function publishedComments()
    {
        return $this->hasMany(Comment::class)
            ->where('approved', true)
            ->orderBy('created_at', 'desc');
    }

    public function activeAuthor()
    {
        return $this->belongsTo(User::class, 'user_id')
            ->where('active', true);
    }

    public function featuredImages()
    {
        return $this->morphMany(Image::class, 'imageable')
            ->where('featured', true)
            ->orderBy('order');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Post.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_type_hinted_relationships(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

class Post extends Model
{
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function comments(): HasMany
    {
        return $this->hasMany(Comment::class);
    }

    public function tags(): BelongsToMany
    {
        return $this->belongsToMany(Tag::class);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Post.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_excludes_protected_and_private_methods(): void
    {
        // 20 protected methods + 5 public business methods = only 5 should count
        $protectedMethods = '';
        for ($i = 1; $i <= 20; $i++) {
            $protectedMethods .= "\n    protected function helper{$i}() { return 'value'; }\n";
        }

        $publicMethods = '';
        for ($i = 1; $i <= 5; $i++) {
            $publicMethods .= "\n    public function businessMethod{$i}() { return 'value'; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
{$protectedMethods}
{$publicMethods}
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/User.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result); // Only 5 public business methods, below threshold
    }

    public function test_excludes_boot_lifecycle_hooks(): void
    {
        $methods = '';
        for ($i = 1; $i <= 13; $i++) {
            $methods .= "\n    public function method{$i}() { return 'value'; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected static function boot()
    {
        parent::boot();
    }

    protected static function booting()
    {
        // Pre-boot logic
    }

    protected static function booted()
    {
        // Post-boot logic
    }
{$methods}
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/User.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result); // 13 methods + 3 boot hooks = 16, but hooks excluded = 13
    }

    public function test_detects_high_complexity_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Order extends Model
{
    public function calculateTotal()
    {
        $total = 0;

        if ($this->hasDiscount()) {
            if ($this->discountType === 'percentage') {
                $total = $this->subtotal * (1 - $this->discount / 100);
            } elseif ($this->discountType === 'fixed') {
                $total = $this->subtotal - $this->discount;
            } elseif ($this->discountType === 'tiered') {
                if ($this->subtotal > 1000) {
                    $total = $this->subtotal * 0.8;
                } elseif ($this->subtotal > 500) {
                    $total = $this->subtotal * 0.9;
                } else {
                    $total = $this->subtotal * 0.95;
                }
            } else {
                $total = $this->subtotal;
            }
        } else {
            $total = $this->subtotal;
        }

        foreach ($this->taxes as $tax) {
            if ($tax->isApplicable()) {
                if ($tax->type === 'vat') {
                    $total += $total * $tax->rate;
                } elseif ($tax->type === 'sales') {
                    $total += $total * 0.05;
                }
            }
        }

        return $total;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Order.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complexity', $result);
    }

    public function test_boundary_exactly_at_method_threshold(): void
    {
        // Exactly 15 methods (at threshold, should pass)
        $methods = '';
        for ($i = 1; $i <= 15; $i++) {
            $methods .= "\n    public function method{$i}() { return 'value'; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Product extends Model
{
{$methods}
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Product.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_boundary_just_over_method_threshold(): void
    {
        // Exactly 16 methods (just over threshold, should fail with low severity)
        $methods = '';
        for ($i = 1; $i <= 16; $i++) {
            $methods .= "\n    public function method{$i}() { return 'value'; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Product extends Model
{
{$methods}
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Product.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(Severity::Low, $issues[0]->severity);
    }

    public function test_severity_escalation_medium_for_many_methods(): void
    {
        // 21 methods (excess = 6, medium severity)
        $methods = '';
        for ($i = 1; $i <= 21; $i++) {
            $methods .= "\n    public function method{$i}() { return 'value'; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Product extends Model
{
{$methods}
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Product.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(Severity::Medium, $issues[0]->severity);
    }

    public function test_severity_escalation_high_for_very_many_methods(): void
    {
        // 31 methods (excess = 16, high severity)
        $methods = '';
        for ($i = 1; $i <= 31; $i++) {
            $methods .= "\n    public function method{$i}() { return 'value'; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Product extends Model
{
{$methods}
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Product.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(Severity::High, $issues[0]->severity);
    }

    public function test_multiple_issues_on_same_model(): void
    {
        // Model with both too many methods AND too many lines
        $methods = '';
        for ($i = 1; $i <= 20; $i++) {
            // Each method has 20 lines
            $methodBody = str_repeat("        // line\n", 20);
            $methods .= "\n    public function method{$i}()\n    {\n{$methodBody}        return 'value';\n    }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Complex extends Model
{
{$methods}
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Complex.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(2, count($issues)); // At least 2 issues
    }

    public function test_supports_custom_base_model(): void
    {
        // Model extending custom BaseModel
        $methods = '';
        for ($i = 1; $i <= 20; $i++) {
            $methods .= "\n    public function method{$i}() { return 'value'; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use App\Models\BaseModel;

class User extends BaseModel
{
{$methods}
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/User.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('business methods', $result);
    }

    public function test_supports_pivot_models(): void
    {
        $methods = '';
        for ($i = 1; $i <= 20; $i++) {
            $methods .= "\n    public function method{$i}() { return 'value'; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Relations\Pivot;

class RoleUser extends Pivot
{
{$methods}
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/RoleUser.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('business methods', $result);
    }

    public function test_empty_model_passes(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Tag extends Model
{
    protected $fillable = ['name'];
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Tag.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_configurable_method_threshold(): void
    {
        // 8 methods with custom threshold of 5
        $methods = '';
        for ($i = 1; $i <= 8; $i++) {
            $methods .= "\n    public function method{$i}() { return 'value'; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Product extends Model
{
{$methods}
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Product.php' => $code]);

        // Custom threshold of 5 (instead of default 15)
        $analyzer = $this->createAnalyzer([
            'fat-model' => [
                'method_threshold' => 5,
            ],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result); // 8 > 5, should fail
        $this->assertHasIssueContaining('threshold: 5', $result);
    }

    public function test_configurable_loc_threshold(): void
    {
        // Create a model with ~150 lines of actual code
        $methods = '';
        for ($i = 1; $i <= 10; $i++) {
            $methodBody = str_repeat("        // line\n", 15);
            $methods .= "\n    public function method{$i}()\n    {\n{$methodBody}        return 'value';\n    }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Order extends Model
{
{$methods}
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Order.php' => $code]);

        // Custom LOC threshold of 100 (instead of default 300)
        $analyzer = $this->createAnalyzer([
            'fat-model' => [
                'loc_threshold' => 100,
            ],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('lines', $result);
    }

    public function test_configurable_complexity_threshold(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Order extends Model
{
    public function process()
    {
        if ($this->status === 'pending') {
            if ($this->hasPayment()) {
                return true;
            } elseif ($this->hasCredit()) {
                return true;
            }
        }
        return false;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Order.php' => $code]);

        // Custom complexity threshold of 3 (instead of default 10)
        $analyzer = $this->createAnalyzer([
            'fat-model' => [
                'complexity_threshold' => 3,
            ],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complexity', $result);
    }
}
