<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PhpParser\Node;
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
}
