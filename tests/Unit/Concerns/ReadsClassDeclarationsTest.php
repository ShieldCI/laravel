<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Concerns;

use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\ParserFactory;
use ShieldCI\Concerns\ReadsClassDeclarations;
use ShieldCI\Concerns\TracksImportedNames;
use ShieldCI\Tests\TestCase;

/**
 * The trait answers about a declaration using the imports of the file it is walking, so it is
 * exercised here through a walk rather than by calling it on a bare node. Both analyzers that
 * use it read it that way.
 */
class ReadsClassDeclarationsTest extends TestCase
{
    /**
     * @return array<string, array{fqn: string|null, ancestors: list<string>, types: array<string, string>, declared: array<string, string>, inheritable: array<string, string>}>
     */
    private function read(string $code): array
    {
        $ast = (new ParserFactory)->createForNewestSupportedVersion()->parse($code);
        $this->assertIsArray($ast);

        $reader = new DeclarationReader;
        $traverser = new NodeTraverser;
        $traverser->addVisitor($reader);
        $traverser->traverse($ast);

        return $reader->seen;
    }

    public function test_names_a_declaration_by_the_namespace_it_is_written_in(): void
    {
        $seen = $this->read('<?php namespace App\Models; use App\Other\Order; class Order {}');

        // The import names a different class of the same short name. A declaration is qualified
        // by its namespace and never by an import, so this is App\Models\Order.
        $this->assertSame('App\Models\Order', $seen['Order']['fqn']);
    }

    public function test_names_a_declaration_in_the_global_namespace(): void
    {
        $seen = $this->read('<?php class Consumer {}');

        $this->assertSame('Consumer', $seen['Consumer']['fqn']);
    }

    public function test_withholds_a_name_from_an_anonymous_class(): void
    {
        $seen = $this->read('<?php namespace App; $x = new class extends Base {};');

        $this->assertNull($seen['@anonymous']['fqn']);
        $this->assertSame(['App\Base'], $seen['@anonymous']['ancestors']);
    }

    public function test_reads_trait_uses_before_the_parent(): void
    {
        // PHP's own precedence: a trait a class uses overrides what it would have inherited.
        $seen = $this->read(
            '<?php namespace App; use App\Support\Caches; class Service extends Base { use Caches, \Other\Logs; }'
        );

        $this->assertSame(['App\Support\Caches', 'Other\Logs', 'App\Base'], $seen['Service']['ancestors']);
    }

    public function test_a_declaration_with_no_parent_and_no_traits_draws_from_nothing(): void
    {
        $seen = $this->read('<?php namespace App; trait Bare { public int $n = 0; }');

        $this->assertSame([], $seen['Bare']['ancestors']);
    }

    public function test_separates_what_a_declaration_can_pass_on_from_everything_it_holds(): void
    {
        $seen = $this->read(<<<'PHP'
<?php

namespace App;

use Illuminate\Contracts\Cache\Repository;

class Holder
{
    public Repository $shared;
    private Repository $own;
    protected ?Repository $nullable = null;
    public $untyped;
    public int $scalar = 0;
    public Repository|string $composite;
}
PHP);

        // Private, untyped and composite entries cannot be put to a single class name from
        // outside, so only the rest are inheritable.
        $this->assertSame(
            ['shared' => 'Illuminate\Contracts\Cache\Repository', 'nullable' => 'Illuminate\Contracts\Cache\Repository'],
            $seen['Holder']['inheritable'],
        );

        // Everything the declaration holds is present in the other view, with the sentinel
        // standing in wherever there is no single name, so nothing can agree by being absent.
        $this->assertSame(
            [
                'shared' => 'Illuminate\Contracts\Cache\Repository',
                'own' => 'Illuminate\Contracts\Cache\Repository',
                'nullable' => 'Illuminate\Contracts\Cache\Repository',
                'untyped' => '?untypable',
                'scalar' => '?untypable',
                'composite' => '?untypable',
            ],
            $seen['Holder']['declared'],
        );

        // And the filtered view drops the sentinel rather than reporting it as a type.
        $this->assertSame(
            [
                'shared' => 'Illuminate\Contracts\Cache\Repository',
                'own' => 'Illuminate\Contracts\Cache\Repository',
                'nullable' => 'Illuminate\Contracts\Cache\Repository',
            ],
            $seen['Holder']['types'],
        );
    }

    public function test_reads_promoted_constructor_parameters_and_ignores_plain_ones(): void
    {
        $seen = $this->read(<<<'PHP'
<?php

namespace App;

use Illuminate\Contracts\Filesystem\Filesystem;

class Writer
{
    public function __construct(
        protected Filesystem $disk,
        private Filesystem $scratch,
        Filesystem $notAProperty,
        private $untypedPromoted,
    ) {}
}
PHP);

        // A plain parameter declares no property, so it appears in neither view.
        $this->assertArrayNotHasKey('notAProperty', $seen['Writer']['declared']);

        $this->assertSame(['disk' => 'Illuminate\Contracts\Filesystem\Filesystem'], $seen['Writer']['inheritable']);
        $this->assertSame(
            [
                'disk' => 'Illuminate\Contracts\Filesystem\Filesystem',
                'scratch' => 'Illuminate\Contracts\Filesystem\Filesystem',
                'untypedPromoted' => '?untypable',
            ],
            $seen['Writer']['declared'],
        );
    }

    public function test_a_method_other_than_the_constructor_declares_no_properties(): void
    {
        $seen = $this->read(
            '<?php namespace App; class Late { public function boot(\App\Disk $disk) {} }'
        );

        $this->assertSame([], $seen['Late']['declared']);
    }
}

/**
 * @internal A host for the trait, since a trait cannot be walked on its own.
 */
class DeclarationReader extends NodeVisitorAbstract
{
    use ReadsClassDeclarations;
    use TracksImportedNames;

    /** @var array<string, array{fqn: string|null, ancestors: list<string>, types: array<string, string>, declared: array<string, string>, inheritable: array<string, string>}> */
    public array $seen = [];

    public function enterNode(Node $node): ?Node
    {
        $this->trackImports($node);

        if ($node instanceof Node\Stmt\ClassLike) {
            $views = $this->propertyViews($node);

            $this->seen[$node->name?->toString() ?? '@anonymous'] = [
                'fqn' => $this->declarationFqn($node),
                'ancestors' => $this->declaredAncestorsOf($node),
                'types' => $this->declaredPropertyTypes($node),
                'declared' => $views['declared'],
                'inheritable' => $views['inheritable'],
            ];
        }

        return null;
    }
}
