<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PHPUnit\Framework\TestCase;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\Support\EloquentModelHelper;

class EloquentModelHelperTest extends TestCase
{
    private AstParser $parser;

    protected function setUp(): void
    {
        parent::setUp();
        $this->parser = new AstParser;
    }

    private function classFrom(string $code): Node\Stmt\Class_
    {
        $ast = $this->parser->parseCode($code);
        $classes = $this->parser->findClasses($ast);
        $this->assertNotEmpty($classes, 'Expected fixture code to contain a class');

        return $classes[0];
    }

    public function test_has_fillable_detects_property(): void
    {
        $class = $this->classFrom('<?php class User { protected $fillable = ["name", "email"]; }');

        $this->assertTrue(EloquentModelHelper::hasFillable($class));
        $this->assertTrue(EloquentModelHelper::hasFillableConfig($class));
        $this->assertFalse(EloquentModelHelper::hasGuarded($class));
    }

    public function test_has_guarded_detects_property(): void
    {
        $class = $this->classFrom('<?php class User { protected $guarded = ["id"]; }');

        $this->assertTrue(EloquentModelHelper::hasGuarded($class));
        $this->assertTrue(EloquentModelHelper::hasFillableConfig($class));
        $this->assertFalse(EloquentModelHelper::hasFillable($class));
    }

    public function test_has_fillable_detects_attribute(): void
    {
        $class = $this->classFrom('<?php use Illuminate\Database\Eloquent\Attributes\Fillable; #[Fillable(["name", "email"])] class User {}');

        $this->assertTrue(EloquentModelHelper::hasFillable($class));
        $this->assertTrue(EloquentModelHelper::hasFillableConfig($class));
    }

    public function test_has_guarded_detects_guarded_attribute(): void
    {
        $class = $this->classFrom('<?php #[Guarded(["id"])] class User {}');

        $this->assertTrue(EloquentModelHelper::hasGuarded($class));
        $this->assertTrue(EloquentModelHelper::hasFillableConfig($class));
    }

    public function test_has_guarded_detects_unguarded_attribute(): void
    {
        $class = $this->classFrom('<?php #[Unguarded] class User {}');

        $this->assertTrue(EloquentModelHelper::hasGuarded($class));
        $this->assertTrue(EloquentModelHelper::hasFillableConfig($class));
    }

    public function test_detects_fully_qualified_attribute(): void
    {
        $class = $this->classFrom('<?php #[\Illuminate\Database\Eloquent\Attributes\Fillable(["name"])] class User {}');

        $this->assertTrue(EloquentModelHelper::hasFillable($class));
    }

    public function test_no_config_when_neither_property_nor_attribute(): void
    {
        $class = $this->classFrom('<?php class User { protected $table = "users"; }');

        $this->assertFalse(EloquentModelHelper::hasFillable($class));
        $this->assertFalse(EloquentModelHelper::hasGuarded($class));
        $this->assertFalse(EloquentModelHelper::hasFillableConfig($class));
    }

    public function test_extract_fillable_fields_from_array_attribute(): void
    {
        $class = $this->classFrom('<?php #[Fillable(["name", "company_id"])] class User {}');

        $this->assertSame(['name', 'company_id'], EloquentModelHelper::extractFillableFieldsFromAttribute($class));
    }

    public function test_extract_fillable_fields_from_variadic_attribute(): void
    {
        $class = $this->classFrom('<?php #[Fillable("title", "user_id")] class Post {}');

        $this->assertSame(['title', 'user_id'], EloquentModelHelper::extractFillableFieldsFromAttribute($class));
    }

    public function test_extract_fillable_fields_returns_empty_without_attribute(): void
    {
        $class = $this->classFrom('<?php class User { protected $fillable = ["name"]; }');

        $this->assertSame([], EloquentModelHelper::extractFillableFieldsFromAttribute($class));
    }

    public function test_has_hidden_detects_property_and_attribute(): void
    {
        $property = $this->classFrom('<?php class User { protected $hidden = ["password"]; }');
        $attribute = $this->classFrom('<?php #[Hidden(["password"])] class User {}');
        $neither = $this->classFrom('<?php class User {}');

        $this->assertTrue(EloquentModelHelper::hasHidden($property));
        $this->assertTrue(EloquentModelHelper::hasHidden($attribute));
        $this->assertFalse(EloquentModelHelper::hasHidden($neither));
    }

    public function test_extract_fillable_fields_reads_property_or_attribute(): void
    {
        $property = $this->classFrom('<?php class User { protected $fillable = ["name", "email"]; }');
        $attribute = $this->classFrom('<?php #[Fillable("name", "email")] class User {}');

        $this->assertSame(['name', 'email'], EloquentModelHelper::extractFillableFields($property));
        $this->assertSame(['name', 'email'], EloquentModelHelper::extractFillableFields($attribute));
    }

    public function test_extract_hidden_fields_reads_property_or_attribute(): void
    {
        $property = $this->classFrom('<?php class User { protected $hidden = ["password", "remember_token"]; }');
        $attribute = $this->classFrom('<?php #[Hidden(["password", "remember_token"])] class User {}');

        $this->assertSame(['password', 'remember_token'], EloquentModelHelper::extractHiddenFields($property));
        $this->assertSame(['password', 'remember_token'], EloquentModelHelper::extractHiddenFields($attribute));
    }

    public function test_extract_guarded_fields_reads_property_or_attribute(): void
    {
        $property = $this->classFrom('<?php class User { protected $guarded = ["id"]; }');
        $attribute = $this->classFrom('<?php #[Guarded(["id"])] class User {}');

        $this->assertSame(['id'], EloquentModelHelper::extractGuardedFields($property));
        $this->assertSame(['id'], EloquentModelHelper::extractGuardedFields($attribute));
    }

    public function test_extraction_skips_methods_and_unrelated_properties(): void
    {
        // The class mixes a non-target property ($table), a method, and the target
        // $fillable so the property/has-property loops must skip non-matching members.
        $class = $this->classFrom(<<<'PHP'
<?php
class User
{
    protected $table = 'users';

    public function scopeActive($query)
    {
        return $query;
    }

    protected $fillable = ['name', 'email'];
}
PHP);

        $this->assertTrue(EloquentModelHelper::hasFillable($class));
        $this->assertSame(['name', 'email'], EloquentModelHelper::extractFillableFields($class));
    }

    public function test_extract_fillable_fields_from_attribute_skips_other_attributes(): void
    {
        // A non-Fillable attribute precedes the Fillable one, exercising the
        // short-name mismatch skip in extractFieldsFromAttribute().
        $class = $this->classFrom('<?php #[Guarded(["id"])] #[Fillable(["name"])] class User {}');

        $this->assertSame(['name'], EloquentModelHelper::extractFillableFieldsFromAttribute($class));
    }

    public function test_extract_eloquent_attribute_fields_matches_the_resolved_name(): void
    {
        // Names are resolved first, so the aliased Fillable is read in both argument shapes and
        // the Appends on the trait is read too, while a Fillable from another namespace is not.
        $traverser = new NodeTraverser;
        $traverser->addVisitor(new NameResolver);
        $ast = $traverser->traverse($this->parser->parseCode(<<<'PHP'
<?php
namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Appends;
use Illuminate\Database\Eloquent\Attributes\Fillable as F;

#[F(['subject', 'html'])]
#[F('teaser')]
#[\App\Attributes\Fillable(['ignored'])]
class Newsletter {}

#[Appends(['excerpt'])]
trait HasExcerpt {}
PHP));

        $declarations = (new NodeFinder)->findInstanceOf($ast, Node\Stmt\ClassLike::class);
        $this->assertCount(2, $declarations);
        $resolve = fn (Node\Name $name): string => $name->toString();

        $this->assertSame(
            ['subject', 'html', 'teaser'],
            EloquentModelHelper::extractEloquentAttributeFields($declarations[0], 'Fillable', $resolve),
        );
        $this->assertSame(
            ['excerpt'],
            EloquentModelHelper::extractEloquentAttributeFields($declarations[1], 'Appends', $resolve),
        );
    }

    public function test_has_and_extract_helpers_match_the_resolved_name_when_given_a_resolver(): void
    {
        // Names are resolved first, so an aliased Laravel attribute is read and a same-named one
        // from another namespace is not.
        $traverser = new NodeTraverser;
        $traverser->addVisitor(new NameResolver);
        $ast = $traverser->traverse($this->parser->parseCode(<<<'PHP'
<?php
namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Fillable as Assignable;
use Illuminate\Database\Eloquent\Attributes\Guarded as Protect;
use Illuminate\Database\Eloquent\Attributes\Unguarded as Open;
use App\Attributes\Hidden;

#[Assignable(['nickname'])]
#[Protect(['role'])]
#[Hidden(['nickname'])]
class Member {}

#[Open]
class Note {}
PHP));

        $classes = (new NodeFinder)->findInstanceOf($ast, Node\Stmt\Class_::class);
        $this->assertCount(2, $classes);
        [$member, $note] = $classes;
        $resolve = fn (Node\Name $name): string => $name->toString();

        $this->assertTrue(EloquentModelHelper::hasFillable($member, $resolve));
        $this->assertTrue(EloquentModelHelper::hasGuarded($member, $resolve));
        $this->assertFalse(EloquentModelHelper::hasHidden($member, $resolve));
        $this->assertTrue(EloquentModelHelper::hasGuarded($note, $resolve));
        $this->assertSame(['nickname'], EloquentModelHelper::extractFillableFields($member, $resolve));
        $this->assertSame(['role'], EloquentModelHelper::extractGuardedFields($member, $resolve));
        $this->assertSame([], EloquentModelHelper::extractHiddenFields($member, $resolve));
    }

    public function test_unguarding_attribute_and_visible_fields_match_the_resolved_name(): void
    {
        $traverser = new NodeTraverser;
        $traverser->addVisitor(new NameResolver);
        $ast = $traverser->traverse($this->parser->parseCode(<<<'PHP'
<?php
namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Guarded;
use Illuminate\Database\Eloquent\Attributes\Unguarded as Open;
use Illuminate\Database\Eloquent\Attributes\Visible as Shown;

#[Guarded([])]
#[Open]
#[Shown(['nickname'])]
class Ledger { protected $visible = ['email']; }

#[Guarded([])]
class Entry {}

#[Guarded(['id'])]
#[Unguarded]
class Note {}
PHP));

        $classes = (new NodeFinder)->findInstanceOf($ast, Node\Stmt\Class_::class);
        $this->assertCount(3, $classes);
        [$ledger, $entry, $note] = $classes;
        $resolve = fn (Node\Name $name): string => $name->toString();

        $this->assertSame('Unguarded', EloquentModelHelper::unguardingAttribute($ledger, $resolve));
        $this->assertSame('Guarded', EloquentModelHelper::unguardingAttribute($entry, $resolve));
        // The unimported #[Unguarded] resolves into App\Models, so it is not Laravel's.
        $this->assertNull(EloquentModelHelper::unguardingAttribute($note, $resolve));
        $this->assertSame(['email', 'nickname'], EloquentModelHelper::extractVisibleFields($ledger, $resolve));
        $this->assertSame([], EloquentModelHelper::extractVisibleFields($entry, $resolve));
    }

    public function test_attribute_fields_are_read_as_constructed_and_matched_ignoring_case(): void
    {
        $traverser = new NodeTraverser;
        $traverser->addVisitor(new NameResolver);
        $ast = $traverser->traverse($this->parser->parseCode(<<<'PHP'
<?php
namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\fillable;
use Illuminate\Database\Eloquent\Attributes\unguarded;

#[fillable(['nickname'], 'password')]
#[unguarded]
class Member {}
PHP));

        $classes = (new NodeFinder)->findInstanceOf($ast, Node\Stmt\Class_::class);
        $this->assertCount(1, $classes);
        $resolve = fn (Node\Name $name): string => $name->toString();

        // Eloquent's constructor keeps only a leading array, so 'password' is not fillable.
        $this->assertSame(['nickname'], EloquentModelHelper::extractFillableFields($classes[0], $resolve));
        $this->assertSame('Unguarded', EloquentModelHelper::unguardingAttribute($classes[0], $resolve));
        // The readers other analyzers call keep returning every argument.
        $this->assertSame(['nickname', 'password'], EloquentModelHelper::extractEloquentAttributeFields($classes[0], 'Fillable', $resolve));
    }

    public function test_own_constants_are_read_as_their_values(): void
    {
        $class = $this->classFrom(<<<'PHP'
<?php
class Voucher
{
    public const LABEL = 'label';
    public const CODES = ['code', self::LABEL];
    protected $fillable = [self::LABEL, Voucher::CODES, ...self::CODES];
    protected $visible = self::CODES;
}
PHP);

        // The plain Voucher::CODES item holds a list, which is not a column name; the spread
        // contributes its entries.
        $this->assertSame(['label', 'code', 'label'], EloquentModelHelper::extractFillableFields($class));
        $this->assertSame(['code', 'label'], EloquentModelHelper::extractVisibleFields($class));
        $this->assertTrue(EloquentModelHelper::fillablePropertyListsColumns($class));
        $this->assertNull(EloquentModelHelper::fillableAttributeListsColumns($class));
        $this->assertFalse(EloquentModelHelper::hasUnreadableEntries($class, 'fillable'));
        $this->assertFalse(EloquentModelHelper::hasUnreadableEntries($class, 'visible'));
    }

    public function test_a_constant_the_class_does_not_declare_is_unreadable(): void
    {
        $class = $this->classFrom(<<<'PHP'
<?php
class Voucher
{
    protected $fillable = [Catalog::LABEL, parent::LABEL, self::INHERITED, Other\Voucher::LABEL];
    protected $hidden = ['token', Column::Secret->value];
}
PHP);

        $this->assertSame([], EloquentModelHelper::extractFillableFields($class));
        $this->assertTrue(EloquentModelHelper::fillablePropertyListsColumns($class));
        $this->assertTrue(EloquentModelHelper::hasUnreadableEntries($class, 'fillable'));
        $this->assertSame(['token'], EloquentModelHelper::extractHiddenFields($class));
        $this->assertTrue(EloquentModelHelper::hasUnreadableEntries($class, 'hidden'));
    }

    public function test_a_class_qualified_constant_in_an_anonymous_class_is_unreadable(): void
    {
        $class = $this->classFrom(<<<'PHP'
<?php
$model = new class {
    public const COLUMNS = ['label'];

    protected $fillable = [...self::COLUMNS, Catalog::LABEL];
};
PHP);

        $this->assertNull($class->name);
        $this->assertSame(['label'], EloquentModelHelper::extractFillableFields($class));
        $this->assertTrue(EloquentModelHelper::hasUnreadableEntries($class, 'fillable'));
    }

    public function test_a_constant_holding_an_empty_list_lists_no_column(): void
    {
        $class = $this->classFrom(<<<'PHP'
<?php
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Guarded;

#[Fillable(self::NONE)]
#[Guarded(self::NONE)]
class Voucher
{
    public const NONE = [];
    protected $fillable = self::NONE;
}
PHP);

        $this->assertFalse(EloquentModelHelper::fillablePropertyListsColumns($class));
        $this->assertFalse(EloquentModelHelper::fillableAttributeListsColumns($class));
        $this->assertSame('Guarded', EloquentModelHelper::unguardingAttribute($class));
    }

    public function test_cyclic_constants_stop_and_read_as_unreadable(): void
    {
        $class = $this->classFrom(<<<'PHP'
<?php
class Voucher
{
    public const FIRST = self::SECOND;
    public const SECOND = self::FIRST;
    public const OUTER = ['label', ...self::INNER];
    public const INNER = [...self::OUTER];
    protected $fillable = self::FIRST;
    protected $visible = self::OUTER;
}
PHP);

        $this->assertSame([], EloquentModelHelper::extractFillableFields($class));
        $this->assertTrue(EloquentModelHelper::hasUnreadableEntries($class, 'fillable'));
        $this->assertSame(['label'], EloquentModelHelper::extractVisibleFields($class));
        $this->assertTrue(EloquentModelHelper::hasUnreadableEntries($class, 'visible'));
    }

    public function test_own_class_name_is_matched_through_the_resolver(): void
    {
        $ast = $this->parser->parseCode(<<<'PHP'
<?php
namespace App\Models;

use App\Catalog\Voucher as Listed;

class Voucher
{
    public const LABEL = 'label';
    protected $fillable = [\App\Models\Voucher::LABEL, Listed::LABEL];
}
PHP);

        $classes = (new NodeFinder)->findInstanceOf($ast, Node\Stmt\Class_::class);
        $this->assertCount(1, $classes);
        $resolve = fn (Node\Name $name): string => match (true) {
            $name->isFullyQualified() => $name->toString(),
            $name->toString() === 'Listed' => 'App\Catalog\Voucher',
            default => 'App\Models\\'.$name->toString(),
        };

        // The import shares the short name but names another class, so its constant is unread.
        $this->assertSame(['label'], EloquentModelHelper::extractFillableFields($classes[0], $resolve));
        $this->assertTrue(EloquentModelHelper::hasUnreadableEntries($classes[0], 'fillable', $resolve));
    }

    public function test_a_leading_own_constant_holding_an_array_is_the_whole_attribute_list(): void
    {
        $class = $this->classFrom(<<<'PHP'
<?php
use Illuminate\Database\Eloquent\Attributes\Fillable;

#[Fillable(self::COLUMNS, 'user_id')]
class Ticket
{
    public const COLUMNS = ['memo'];
}
PHP);

        // Eloquent's constructor keeps only a leading array, so 'user_id' is not fillable.
        $this->assertSame(['memo'], EloquentModelHelper::extractFillableFields($class));
    }
}
