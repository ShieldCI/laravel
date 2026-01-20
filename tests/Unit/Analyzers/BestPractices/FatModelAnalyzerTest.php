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
                    'best-practices' => $config,
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

    public function test_detects_model_with_alias(): void
    {
        $methods = '';
        for ($i = 1; $i <= 20; $i++) {
            $methods .= "\n    public function method{$i}() { return 'value'; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model as Eloquent;

class Product extends Eloquent
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
        $this->assertHasIssueContaining('business methods', $result);
    }

    public function test_detects_authenticatable_model(): void
    {
        $methods = '';
        for ($i = 1; $i <= 20; $i++) {
            $methods .= "\n    public function method{$i}() { return 'value'; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
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

    public function test_detects_morph_pivot_model(): void
    {
        $methods = '';
        for ($i = 1; $i <= 20; $i++) {
            $methods .= "\n    public function method{$i}() { return 'value'; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Relations\MorphPivot;

class Taggable extends MorphPivot
{
{$methods}
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Taggable.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('business methods', $result);
    }

    public function test_excludes_casts_method(): void
    {
        // Model with casts() method (Laravel 11+) and 14 business methods (under threshold)
        $methods = '';
        for ($i = 1; $i <= 14; $i++) {
            $methods .= "\n    public function method{$i}() { return 'value'; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }
{$methods}
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/User.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result); // 14 business methods (casts excluded), under threshold of 15
    }

    public function test_excludes_morphed_by_many_relationship(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphedByMany;

class Tag extends Model
{
    public function posts(): MorphedByMany
    {
        return $this->morphedByMany(Post::class, 'taggable');
    }

    public function videos(): MorphedByMany
    {
        return $this->morphedByMany(Video::class, 'taggable');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Tag.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_nullable_return_type_relationship(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Post extends Model
{
    public function comments(): ?HasMany
    {
        return $this->hasMany(Comment::class);
    }

    public function likes(): ?HasMany
    {
        return $this->hasMany(Like::class);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Post.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result); // Nullable relationships should be excluded
    }

    public function test_detects_union_return_type_relationship(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Comment extends Model
{
    public function author(): HasMany|BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Comment.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result); // Union type relationships should be excluded
    }

    public function test_complexity_severity_scales_with_excess(): void
    {
        // Create a method with very high complexity (26+, which is 16+ over threshold of 10)
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Order extends Model
{
    public function extremelyComplexMethod()
    {
        $result = 0;

        // 15+ decision points to get to high severity
        if ($a) { $result++; }
        if ($b) { $result++; }
        if ($c) { $result++; }
        if ($d) { $result++; }
        if ($e) { $result++; }
        if ($f) { $result++; }
        if ($g) { $result++; }
        if ($h) { $result++; }
        if ($i) { $result++; }
        if ($j) { $result++; }
        if ($k) { $result++; }
        if ($l) { $result++; }
        if ($m) { $result++; }
        if ($n) { $result++; }
        if ($o) { $result++; }
        if ($p) { $result++; }
        if ($q) { $result++; }
        if ($r) { $result++; }
        if ($s) { $result++; }
        if ($t) { $result++; }
        if ($u) { $result++; }
        if ($v) { $result++; }
        if ($w) { $result++; }
        if ($x) { $result++; }
        if ($y) { $result++; }

        return $result;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Order.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(Severity::High, $issues[0]->severity);
    }

    public function test_counts_coalesce_operator_in_complexity(): void
    {
        // Create a method that uses null coalesce operators to increase complexity
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Settings extends Model
{
    public function getValue()
    {
        // Base complexity: 1
        // Each ?? adds 1: 12 coalesce operators
        // Total: 13, exceeds threshold of 10
        return $this->a ?? $this->b ?? $this->c ?? $this->d ?? $this->e
            ?? $this->f ?? $this->g ?? $this->h ?? $this->i ?? $this->j
            ?? $this->k ?? $this->l ?? 'default';
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Settings.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complexity', $result);
    }

    public function test_counts_match_expression_in_complexity(): void
    {
        // Create a method that uses PHP 8 match expression
        $code = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Status extends Model
{
    public function getLabel()
    {
        // Base: 1
        // match adds: 1
        // Each arm with condition adds: 1 per condition
        // 10 arms = 10 complexity points
        // Total: 12, exceeds threshold of 10
        return match ($this->status) {
            'pending' => 'Pending',
            'processing' => 'Processing',
            'shipped' => 'Shipped',
            'delivered' => 'Delivered',
            'cancelled' => 'Cancelled',
            'refunded' => 'Refunded',
            'returned' => 'Returned',
            'failed' => 'Failed',
            'on_hold' => 'On Hold',
            'completed' => 'Completed',
            default => 'Unknown',
        };
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Status.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('complexity', $result);
    }

    public function test_result_message_shows_unique_model_count(): void
    {
        // Create two fat models with multiple issues each
        $methods1 = '';
        for ($i = 1; $i <= 20; $i++) {
            $methods1 .= "\n    public function method{$i}() { return 'value'; }\n";
        }

        $methods2 = '';
        for ($i = 1; $i <= 18; $i++) {
            $methods2 .= "\n    public function method{$i}() { return 'value'; }\n";
        }

        $code1 = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Product extends Model
{
{$methods1}
}
PHP;

        $code2 = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Order extends Model
{
{$methods2}
}
PHP;

        $tempDir = $this->createTempDirectory([
            'Models/Product.php' => $code1,
            'Models/Order.php' => $code2,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        // Should show "2 issue(s) across 2 fat model(s)"
        $this->assertStringContainsString('2 issue(s)', $result->getMessage());
        $this->assertStringContainsString('2 fat model(s)', $result->getMessage());
    }

    public function test_excludes_route_model_binding_methods(): void
    {
        // Model with route model binding methods (should be excluded)
        $methods = '';
        for ($i = 1; $i <= 12; $i++) {
            $methods .= "\n    public function method{$i}() { return 'value'; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    public function resolveRouteBinding(\$value, \$field = null)
    {
        return \$this->where(\$field ?? 'slug', \$value)->firstOrFail();
    }

    public function resolveChildRouteBinding(\$childType, \$value, \$field)
    {
        return parent::resolveChildRouteBinding(\$childType, \$value, \$field);
    }

    public function getRouteKeyName()
    {
        return 'slug';
    }

    public function getRouteKey()
    {
        return \$this->slug;
    }
{$methods}
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/User.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result); // 12 business + 4 route methods = 16, but route methods excluded = 12
    }

    public function test_excludes_serialization_methods(): void
    {
        // Model with toArray and toJson (should be excluded)
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
    public function toArray()
    {
        return array_merge(parent::toArray(), ['custom' => 'value']);
    }

    public function toJson(\$options = 0)
    {
        return json_encode(\$this->toArray(), \$options);
    }
{$methods}
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/User.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result); // 13 business + 2 serialization methods = 15, but serialization excluded = 13
    }

    public function test_excludes_scout_searchable_methods(): void
    {
        // Model with Scout searchable methods (should be excluded)
        $methods = '';
        for ($i = 1; $i <= 12; $i++) {
            $methods .= "\n    public function method{$i}() { return 'value'; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Laravel\Scout\Searchable;

class Post extends Model
{
    use Searchable;

    public function shouldBeSearchable()
    {
        return \$this->isPublished();
    }

    public function toSearchableArray()
    {
        return ['title' => \$this->title, 'content' => \$this->content];
    }

    public function searchableAs()
    {
        return 'posts_index';
    }
{$methods}
}
PHP;

        $tempDir = $this->createTempDirectory(['Models/Post.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result); // 12 business + 3 scout methods = 15, but scout methods excluded = 12
    }

    public function test_detects_namespace_relative_parent_class(): void
    {
        // Model using namespace-relative path like Foundation\Auth\User
        // where Foundation is imported via `use Illuminate\Foundation`
        $methods = '';
        for ($i = 1; $i <= 20; $i++) {
            $methods .= "\n    public function method{$i}() { return 'value'; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Foundation;

class User extends Foundation\Auth\User
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

    public function test_detects_namespace_relative_model_parent(): void
    {
        // Model using namespace-relative path like Database\Eloquent\Model
        // where Database is imported via `use Illuminate\Database`
        $methods = '';
        for ($i = 1; $i <= 20; $i++) {
            $methods .= "\n    public function method{$i}() { return 'value'; }\n";
        }

        $code = <<<PHP
<?php

namespace App\Models;

use Illuminate\Database;

class Product extends Database\Eloquent\Model
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
        $this->assertHasIssueContaining('business methods', $result);
    }
}
