<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use PhpParser\Node;

/**
 * Helpers for reading Eloquent model mass-assignment configuration from an AST.
 *
 * Laravel exposes mass-assignment configuration in two interchangeable ways:
 *  - the classic protected properties: `protected $fillable = [...]` / `protected $guarded = [...]`
 *  - first-class attributes (Laravel 12+): `#[Fillable(...)]`, `#[Guarded(...)]`, `#[Unguarded]`
 *
 * Analyzers that only inspect properties produce false positives on attribute-based
 * models. These helpers read both forms so callers don't have to.
 */
final class EloquentModelHelper
{
    /**
     * True if the class declares fillable OR guarded configuration in either form.
     */
    public static function hasFillableConfig(Node\Stmt\Class_ $class): bool
    {
        return self::hasFillable($class) || self::hasGuarded($class);
    }

    /**
     * True if a `$fillable` property OR a `#[Fillable]` attribute is present.
     */
    public static function hasFillable(Node\Stmt\Class_ $class): bool
    {
        return self::hasProperty($class, 'fillable')
            || self::hasAttribute($class, ['Fillable']);
    }

    /**
     * True if a `$guarded` property OR a `#[Guarded]`/`#[Unguarded]` attribute is present.
     */
    public static function hasGuarded(Node\Stmt\Class_ $class): bool
    {
        return self::hasProperty($class, 'guarded')
            || self::hasAttribute($class, ['Guarded', 'Unguarded']);
    }

    /**
     * True if a `$hidden` property OR a `#[Hidden]` attribute is present.
     */
    public static function hasHidden(Node\Stmt\Class_ $class): bool
    {
        return self::hasProperty($class, 'hidden')
            || self::hasAttribute($class, ['Hidden']);
    }

    /**
     * Fillable field names from a `$fillable` property OR `#[Fillable(...)]` attribute.
     *
     * @return list<string>
     */
    public static function extractFillableFields(Node\Stmt\Class_ $class): array
    {
        return array_values(array_merge(
            self::extractFieldsFromProperty($class, 'fillable'),
            self::extractFillableFieldsFromAttribute($class),
        ));
    }

    /**
     * Guarded field names from a `$guarded` property OR `#[Guarded(...)]` attribute.
     *
     * @return list<string>
     */
    public static function extractGuardedFields(Node\Stmt\Class_ $class): array
    {
        return array_values(array_merge(
            self::extractFieldsFromProperty($class, 'guarded'),
            self::extractFieldsFromAttribute($class, 'Guarded'),
        ));
    }

    /**
     * Hidden field names from a `$hidden` property OR `#[Hidden(...)]` attribute.
     *
     * @return list<string>
     */
    public static function extractHiddenFields(Node\Stmt\Class_ $class): array
    {
        return array_values(array_merge(
            self::extractFieldsFromProperty($class, 'hidden'),
            self::extractFieldsFromAttribute($class, 'Hidden'),
        ));
    }

    /**
     * Field names declared by a `#[Fillable(...)]` attribute.
     *
     * Handles both constructor shapes:
     *   #[Fillable(['user_id', 'title'])]  -> single arg whose value is an array literal
     *   #[Fillable('user_id', 'title')]    -> multiple string args (variadic)
     *
     * Returns an empty list when no `#[Fillable]` attribute is present.
     *
     * @return list<string>
     */
    public static function extractFillableFieldsFromAttribute(Node\Stmt\Class_ $class): array
    {
        return self::extractFieldsFromAttribute($class, 'Fillable');
    }

    /**
     * String field names from a class-level attribute, handling both the array
     * (`#[Attr(['a', 'b'])]`) and variadic (`#[Attr('a', 'b')]`) constructor shapes.
     *
     * @return list<string>
     */
    private static function extractFieldsFromAttribute(Node\Stmt\Class_ $class, string $attributeShortName): array
    {
        $fields = [];

        foreach (self::attributes($class) as $attr) {
            if (self::shortName($attr->name->toString()) !== $attributeShortName) {
                continue;
            }

            foreach ($attr->args as $arg) {
                if ($arg->value instanceof Node\Expr\Array_) {
                    foreach ($arg->value->items as $item) {
                        if ($item instanceof Node\Expr\ArrayItem && $item->value instanceof Node\Scalar\String_) {
                            $fields[] = $item->value->value;
                        }
                    }
                } elseif ($arg->value instanceof Node\Scalar\String_) {
                    $fields[] = $arg->value->value;
                }
            }
        }

        return $fields;
    }

    /**
     * String field names from a `protected $name = [...]` array property.
     *
     * @return list<string>
     */
    private static function extractFieldsFromProperty(Node\Stmt\Class_ $class, string $name): array
    {
        $fields = [];

        foreach ($class->stmts as $stmt) {
            if (! $stmt instanceof Node\Stmt\Property) {
                continue;
            }

            foreach ($stmt->props as $prop) {
                if ($prop->name->toString() !== $name || ! $prop->default instanceof Node\Expr\Array_) {
                    continue;
                }

                foreach ($prop->default->items as $item) {
                    if ($item instanceof Node\Expr\ArrayItem && $item->value instanceof Node\Scalar\String_) {
                        $fields[] = $item->value->value;
                    }
                }
            }
        }

        return $fields;
    }

    /**
     * True if the class defines a property with the given name.
     */
    private static function hasProperty(Node\Stmt\Class_ $class, string $name): bool
    {
        foreach ($class->stmts as $stmt) {
            if (! $stmt instanceof Node\Stmt\Property) {
                continue;
            }

            foreach ($stmt->props as $prop) {
                if ($prop->name->toString() === $name) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * True if the class carries any class-level attribute whose short name matches one of $names.
     *
     * @param  list<string>  $names
     */
    private static function hasAttribute(Node\Stmt\Class_ $class, array $names): bool
    {
        foreach (self::attributes($class) as $attr) {
            if (in_array(self::shortName($attr->name->toString()), $names, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * All class-level attributes on the class.
     *
     * @return list<Node\Attribute>
     */
    private static function attributes(Node\Stmt\Class_ $class): array
    {
        $attributes = [];

        foreach ($class->attrGroups as $group) {
            foreach ($group->attrs as $attr) {
                $attributes[] = $attr;
            }
        }

        return $attributes;
    }

    /**
     * Last `\`-separated segment of a name (attributes are usually written unqualified
     * after a `use` import).
     */
    private static function shortName(string $name): string
    {
        $pos = strrpos($name, '\\');

        return $pos === false ? $name : substr($name, $pos + 1);
    }
}
