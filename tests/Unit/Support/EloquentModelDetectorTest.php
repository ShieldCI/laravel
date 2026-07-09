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

    /** @var array<int, string> */
    private array $tempDirs = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->detector = new EloquentModelDetector(new AstParser);
    }

    protected function tearDown(): void
    {
        foreach ($this->tempDirs as $dir) {
            $this->removeDir($dir);
        }
        $this->tempDirs = [];

        parent::tearDown();
    }

    /**
     * @param  array<string, string>  $files  relative path => contents
     */
    private function createTempDir(array $files): string
    {
        $dir = sys_get_temp_dir().'/eloquent_model_detector_test_'.uniqid();
        mkdir($dir, 0755, true);
        $this->tempDirs[] = $dir;

        foreach ($files as $relative => $contents) {
            $path = $dir.'/'.$relative;
            $parent = dirname($path);
            if (! is_dir($parent)) {
                mkdir($parent, 0755, true);
            }
            file_put_contents($path, $contents);
        }

        return $dir;
    }

    private function removeDir(string $dir): void
    {
        if (! is_dir($dir)) {
            return;
        }

        $entries = scandir($dir);
        if ($entries === false) {
            return;
        }

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = $dir.'/'.$entry;
            is_dir($path) ? $this->removeDir($path) : unlink($path);
        }

        rmdir($dir);
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

    public function test_parent_in_a_models_namespace_is_a_model(): void
    {
        [$class, $ast] = $this->parseClass(<<<'PHP'
<?php
namespace App\Models;
use Spatie\Permission\Models\Role as SpatieRole;
class Role extends SpatieRole {}
PHP);

        $this->assertTrue($this->detector->verdictFor($class, $ast, '/nonexistent'));
    }

    public function test_own_models_namespace_rescues_a_vendor_base(): void
    {
        [$class, $ast] = $this->parseClass(<<<'PHP'
<?php
namespace App\Models;
use Laravel\Cashier\Subscription as CashierSubscription;
class Subscription extends CashierSubscription {}
PHP);

        $this->assertTrue($this->detector->verdictFor($class, $ast, '/nonexistent'));
    }

    public function test_modular_models_namespace_is_a_model(): void
    {
        [$class, $ast] = $this->parseClass(<<<'PHP'
<?php
namespace Modules\Billing\Models;
use Vendor\Base\Entity;
class Customer extends Entity {}
PHP);

        $this->assertTrue($this->detector->verdictFor($class, $ast, '/nonexistent'));
    }

    public function test_chain_walk_resolves_a_project_base_model(): void
    {
        // Both child and parent live OUTSIDE any Models namespace, so neither step 4
        // (parent's own Models namespace) nor step 6 (analyzed class's own Models
        // namespace) can produce the verdict. The only way to reach `true` is step 5
        // actually reading RecordBase.php off disk and finding it extends Model.
        $base = <<<'PHP'
<?php
namespace App\Domain;
use Illuminate\Database\Eloquent\Model;
abstract class RecordBase extends Model {}
PHP;

        $child = <<<'PHP'
<?php
namespace App\Domain;
use App\Domain\RecordBase;
class Order extends RecordBase {}
PHP;

        $dir = $this->createTempDir(['app/Domain/RecordBase.php' => $base]);
        [$class, $ast] = $this->parseClass($child);

        $this->assertTrue($this->detector->verdictFor($class, $ast, $dir));
    }

    public function test_chain_walk_returns_definitive_false_for_a_view_model_base(): void
    {
        $base = <<<'PHP'
<?php
namespace App\ViewModels;
abstract class BaseViewModel {}
PHP;

        $child = <<<'PHP'
<?php
namespace App\ViewModels;
class ProductPage extends BaseViewModel {}
PHP;

        $dir = $this->createTempDir(['app/ViewModels/BaseViewModel.php' => $base]);
        [$class, $ast] = $this->parseClass($child);

        $this->assertFalse($this->detector->verdictFor($class, $ast, $dir));
    }

    public function test_chain_false_outranks_the_models_namespace_convention(): void
    {
        $base = <<<'PHP'
<?php
namespace App\Support;
class Base {}
PHP;

        $child = <<<'PHP'
<?php
namespace App\Models;
use App\Support\Base;
class Dto extends Base {}
PHP;

        $dir = $this->createTempDir(['app/Support/Base.php' => $base]);
        [$class, $ast] = $this->parseClass($child);

        $this->assertFalse(
            $this->detector->verdictFor($class, $ast, $dir),
            'a resolved chain terminating at a non-model must beat the App\Models convention'
        );
    }

    public function test_unknown_when_chain_leaves_the_project(): void
    {
        [$class, $ast] = $this->parseClass(<<<'PHP'
<?php
namespace Domain\Billing;
use Laravel\Cashier\Subscription;
class Invoice extends Subscription {}
PHP);

        $this->assertNull($this->detector->verdictFor($class, $ast, '/nonexistent'));
    }

    public function test_cyclic_extends_chain_terminates_with_unknown(): void
    {
        $a = <<<'PHP'
<?php
namespace App\Support;
class A extends B {}
PHP;

        $b = <<<'PHP'
<?php
namespace App\Support;
class B extends A {}
PHP;

        $dir = $this->createTempDir([
            'app/Support/A.php' => $a,
            'app/Support/B.php' => $b,
        ]);

        [$class, $ast] = $this->parseClass($a);

        $this->assertNull($this->detector->verdictFor($class, $ast, $dir));
    }

    public function test_deep_chain_and_shared_instance_do_not_poison_cache(): void
    {
        // Chain of 6 hops to Model (L0->L1->L2->L3->L4->L5->Model), deeper than the old
        // MAX_INHERITANCE_DEPTH=5 cap. All classes live outside any Models namespace so
        // only the actual chain walk can produce a verdict, never the namespace convention.
        $dir = $this->createTempDir([
            'app/Chain/L1.php' => <<<'PHP'
<?php
namespace App\Chain;
class L1 extends L2 {}
PHP,
            'app/Chain/L2.php' => <<<'PHP'
<?php
namespace App\Chain;
class L2 extends L3 {}
PHP,
            'app/Chain/L3.php' => <<<'PHP'
<?php
namespace App\Chain;
class L3 extends L4 {}
PHP,
            'app/Chain/L4.php' => <<<'PHP'
<?php
namespace App\Chain;
class L4 extends L5 {}
PHP,
            'app/Chain/L5.php' => <<<'PHP'
<?php
namespace App\Chain;
use Illuminate\Database\Eloquent\Model;
class L5 extends Model {}
PHP,
        ]);

        [$topClass, $topAst] = $this->parseClass(<<<'PHP'
<?php
namespace App\Chain;
class L0 extends L1 {}
PHP);

        $this->assertTrue(
            $this->detector->verdictFor($topClass, $topAst, $dir),
            'a 6-hop chain to Model must resolve to true now that the depth cap is gone'
        );

        // Same detector instance, same directory: a fresh class extending a mid-chain
        // ancestor (L4, two hops from Model) must still resolve to true. Before the fix,
        // the verdictFor(L0) call above would have poisoned the cache entry for L4's file
        // with a stale, budget-starved null, and this assertion would wrongly get null.
        [$midClass, $midAst] = $this->parseClass(<<<'PHP'
<?php
namespace App\Chain;
class M0 extends L4 {}
PHP);

        $this->assertTrue(
            $this->detector->verdictFor($midClass, $midAst, $dir),
            'the shared cache from the deep-chain call above must not poison a later, shallower lookup'
        );
    }

    public function test_is_model_maps_unknown_to_the_callers_default(): void
    {
        [$class, $ast] = $this->parseClass(<<<'PHP'
<?php
namespace Domain\Billing;
use Laravel\Cashier\Subscription;
class Invoice extends Subscription {}
PHP);

        $this->assertNull($this->detector->verdictFor($class, $ast, '/nonexistent'));
        $this->assertFalse($this->detector->isModel($class, $ast, '/nonexistent'));
        $this->assertFalse($this->detector->isModel($class, $ast, '/nonexistent', unknownIs: false));
        $this->assertTrue($this->detector->isModel($class, $ast, '/nonexistent', unknownIs: true));
    }

    public function test_is_model_ignores_the_default_for_definite_verdicts(): void
    {
        [$model, $modelAst] = $this->parseClass(<<<'PHP'
<?php
namespace App\Models;
use Illuminate\Database\Eloquent\Model;
class Post extends Model {}
PHP);

        [$plain, $plainAst] = $this->parseClass(<<<'PHP'
<?php
namespace App\Support;
class ActiveBusiness {}
PHP);

        $this->assertTrue($this->detector->isModel($model, $modelAst, '/nonexistent', unknownIs: false));
        $this->assertFalse($this->detector->isModel($plain, $plainAst, '/nonexistent', unknownIs: true));
    }

    public function test_chain_walk_into_an_empty_parent_file_yields_unknown(): void
    {
        // The parent file exists (so the chain walk reads it) but parses to an empty
        // AST — e.g. a stub containing only the opening tag. fileVerdict() returns null
        // for that file, and with neither class in a Models namespace the verdict is unknown.
        $dir = $this->createTempDir([
            'app/Support/EmptyBase.php' => "<?php\n",
        ]);

        [$class, $ast] = $this->parseClass(<<<'PHP'
<?php
namespace App\Entities;
use App\Support\EmptyBase;
class Order extends EmptyBase {}
PHP);

        $this->assertNull($this->detector->verdictFor($class, $ast, $dir));
    }

    public function test_global_class_extending_an_unresolvable_bare_name_is_unknown(): void
    {
        // No namespace, no import: the parent name "Bar" cannot be resolved to an FQN
        // (not qualified, absent from the use map, no enclosing namespace to prefix with),
        // so the verdict is unknown rather than a guess. Also exercises extractNamespace()
        // returning null for a file that declares no namespace.
        [$class, $ast] = $this->parseClass(<<<'PHP'
<?php
class Foo extends Bar {}
PHP);

        $this->assertNull($this->detector->verdictFor($class, $ast, '/nonexistent'));
    }

    public function test_aliased_eloquent_base_imported_via_group_use_is_a_model(): void
    {
        // Group-use syntax `use A\{Model as Eloquent};` — the parent short name "Eloquent"
        // is not a base, so resolution must go through the grouped import map to reach the
        // Eloquent base FQN at step 3.
        [$class, $ast] = $this->parseClass(<<<'PHP'
<?php
namespace App\Domain;
use Illuminate\Database\Eloquent\{Model as Eloquent};
class Invoice extends Eloquent {}
PHP);

        $this->assertTrue($this->detector->verdictFor($class, $ast, '/nonexistent'));
    }
}
