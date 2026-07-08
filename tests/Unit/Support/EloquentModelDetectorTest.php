<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PhpParser\Node;
use PhpParser\Node\Stmt\Class_;
use PHPUnit\Framework\TestCase;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\Support\EloquentModelDetector;

class EloquentModelDetectorTest extends TestCase
{
    private EloquentModelDetector $detector;

    protected function setUp(): void
    {
        parent::setUp();
        $this->detector = new EloquentModelDetector(new AstParser);
    }

    public function test_namespace_looks_like_models_accepts_app_models(): void
    {
        $this->assertTrue($this->detector->namespaceLooksLikeModels('App\\Models'));
    }

    public function test_namespace_looks_like_models_accepts_nested_and_modular(): void
    {
        $this->assertTrue($this->detector->namespaceLooksLikeModels('App\\Models\\Admin'));
        $this->assertTrue($this->detector->namespaceLooksLikeModels('Modules\\Billing\\Models'));
    }

    public function test_namespace_looks_like_models_rejects_view_models(): void
    {
        $this->assertFalse($this->detector->namespaceLooksLikeModels('App\\ViewModels'));
    }

    public function test_namespace_looks_like_models_rejects_helper_subnamespaces(): void
    {
        foreach (['Scopes', 'Observers', 'Casts', 'Collections', 'Traits', 'Concerns', 'Builders', 'Enums'] as $helper) {
            $this->assertFalse(
                $this->detector->namespaceLooksLikeModels('App\\Models\\'.$helper),
                $helper.' must not qualify'
            );
        }
    }

    public function test_namespace_looks_like_models_rejects_null_and_empty(): void
    {
        $this->assertFalse($this->detector->namespaceLooksLikeModels(null));
        $this->assertFalse($this->detector->namespaceLooksLikeModels(''));
    }

    /**
     * Parse $code and return [firstClassNode, fullFileAst].
     *
     * @return array{0: Class_, 1: array<Node>}
     */
    private function parseClass(string $code): array
    {
        $parser = new AstParser;
        $ast = $parser->parseCode($code);
        $classes = $parser->findClasses($ast);

        $this->assertNotEmpty($classes, 'fixture must declare a class');

        return [$classes[0], $ast];
    }

    public function test_class_with_no_parent_is_definitively_not_a_model(): void
    {
        [$class, $ast] = $this->parseClass(<<<'PHP'
<?php
namespace App\Support;
class ActiveBusiness {}
PHP);

        $this->assertFalse($this->detector->verdictFor($class, $ast, '/nonexistent'));
    }

    public function test_extends_model_short_name_is_a_model(): void
    {
        [$class, $ast] = $this->parseClass(<<<'PHP'
<?php
namespace App\Models;
use Illuminate\Database\Eloquent\Model;
class Post extends Model {}
PHP);

        $this->assertTrue($this->detector->verdictFor($class, $ast, '/nonexistent'));
    }

    public function test_extends_pivot_authenticatable_and_morph_pivot_are_models(): void
    {
        foreach (['Pivot', 'MorphPivot', 'Authenticatable'] as $base) {
            [$class, $ast] = $this->parseClass(<<<PHP
<?php
namespace App\Models;
class Thing extends {$base} {}
PHP);

            $this->assertTrue(
                $this->detector->verdictFor($class, $ast, '/nonexistent'),
                $base.' must be an Eloquent base'
            );
        }
    }

    public function test_fully_qualified_eloquent_base_is_a_model(): void
    {
        [$class, $ast] = $this->parseClass(<<<'PHP'
<?php
namespace App\Entities;
class Post extends \Illuminate\Database\Eloquent\Model {}
PHP);

        $this->assertTrue($this->detector->verdictFor($class, $ast, '/nonexistent'));
    }

    public function test_aliased_eloquent_import_is_a_model(): void
    {
        [$class, $ast] = $this->parseClass(<<<'PHP'
<?php
namespace App\Domain\Billing;
use Illuminate\Database\Eloquent\Model as Eloquent;
class Invoice extends Eloquent {}
PHP);

        $this->assertTrue($this->detector->verdictFor($class, $ast, '/nonexistent'));
    }

    public function test_fully_qualified_authenticatable_resolves_via_fqn_pass_through(): void
    {
        // Short name "User" is NOT an Eloquent base short name, so step 2 cannot match.
        // The parent is a FullyQualified name, so resolveClassName() passes it through
        // unchanged and the verdict can only come from the step-3 FQN match — the exact
        // branch that keeps the detector correct for callers that ran NameResolver.
        [$class, $ast] = $this->parseClass(<<<'PHP'
<?php
namespace App\Auth;
class Admin extends \Illuminate\Foundation\Auth\User {}
PHP);

        $this->assertTrue($this->detector->verdictFor($class, $ast, '/nonexistent'));
    }
}
