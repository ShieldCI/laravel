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
 *
 * An attribute is matched on its short name as written unless the caller passes $resolve,
 * the fully qualified name a reference resolves to in the declaring file. With it, the
 * attribute must resolve into Illuminate\Database\Eloquent\Attributes, so an aliased import
 * (`use ...\Fillable as F;`) is read and a `Fillable` from any other namespace is not.
 */
final class EloquentModelHelper
{
    /**
     * The namespace Eloquent's own class attributes are declared in.
     */
    private const ATTRIBUTE_NAMESPACE = 'Illuminate\Database\Eloquent\Attributes';

    /**
     * True if the class declares fillable OR guarded configuration in either form.
     */
    public static function hasFillableConfig(Node\Stmt\Class_ $class): bool
    {
        return self::hasFillable($class) || self::hasGuarded($class);
    }

    /**
     * True if a `$fillable` property OR a `#[Fillable]` attribute is present.
     *
     * @param  (\Closure(Node\Name): string)|null  $resolve  The fully qualified name a reference resolves to
     */
    public static function hasFillable(Node\Stmt\Class_ $class, ?\Closure $resolve = null): bool
    {
        return self::hasProperty($class, 'fillable')
            || self::hasAttribute($class, ['Fillable'], $resolve);
    }

    /**
     * True if a `$guarded` property OR a `#[Guarded]`/`#[Unguarded]` attribute is present.
     *
     * @param  (\Closure(Node\Name): string)|null  $resolve  The fully qualified name a reference resolves to
     */
    public static function hasGuarded(Node\Stmt\Class_ $class, ?\Closure $resolve = null): bool
    {
        return self::hasProperty($class, 'guarded')
            || self::hasAttribute($class, ['Guarded', 'Unguarded'], $resolve);
    }

    /**
     * True if a `$hidden` property OR a `#[Hidden]` attribute is present.
     *
     * @param  (\Closure(Node\Name): string)|null  $resolve  The fully qualified name a reference resolves to
     */
    public static function hasHidden(Node\Stmt\Class_ $class, ?\Closure $resolve = null): bool
    {
        return self::hasProperty($class, 'hidden')
            || self::hasAttribute($class, ['Hidden'], $resolve);
    }

    /**
     * The Eloquent attribute that leaves the class with nothing guarded: `Unguarded` for
     * `#[Unguarded]`, `Guarded` for a `#[Guarded([])]` whose only argument is an empty array
     * literal, null for neither. `#[Unguarded]` wins when both are present, as it does in
     * GuardsAttributes.
     *
     * Laravel applies either only while the `$guarded` property still holds its `['*']`
     * default, so whether a declared `$guarded` overrides it is the caller's to decide.
     *
     * @param  (\Closure(Node\Name): string)|null  $resolve  The fully qualified name a reference resolves to
     */
    public static function unguardingAttribute(Node\Stmt\Class_ $class, ?\Closure $resolve = null): ?string
    {
        $emptyGuarded = false;

        foreach (self::attributes($class) as $attr) {
            if (self::attributeIs($attr, 'Unguarded', $resolve)) {
                return 'Unguarded';
            }

            if (self::attributeIs($attr, 'Guarded', $resolve)
                && count($attr->args) === 1
                && $attr->args[0]->value instanceof Node\Expr\Array_
                && $attr->args[0]->value->items === []) {
                $emptyGuarded = true;
            }
        }

        return $emptyGuarded ? 'Guarded' : null;
    }

    /**
     * Fillable field names from a `$fillable` property OR `#[Fillable(...)]` attribute.
     *
     * @param  (\Closure(Node\Name): string)|null  $resolve  The fully qualified name a reference resolves to
     * @return list<string>
     */
    public static function extractFillableFields(Node\Stmt\Class_ $class, ?\Closure $resolve = null): array
    {
        return array_values(array_merge(
            self::extractFieldsFromProperty($class, 'fillable'),
            self::extractFieldsFromAttribute($class, 'Fillable', $resolve),
        ));
    }

    /**
     * Guarded field names from a `$guarded` property OR `#[Guarded(...)]` attribute.
     *
     * @param  (\Closure(Node\Name): string)|null  $resolve  The fully qualified name a reference resolves to
     * @return list<string>
     */
    public static function extractGuardedFields(Node\Stmt\Class_ $class, ?\Closure $resolve = null): array
    {
        return array_values(array_merge(
            self::extractFieldsFromProperty($class, 'guarded'),
            self::extractFieldsFromAttribute($class, 'Guarded', $resolve),
        ));
    }

    /**
     * Hidden field names from a `$hidden` property OR `#[Hidden(...)]` attribute.
     *
     * @param  (\Closure(Node\Name): string)|null  $resolve  The fully qualified name a reference resolves to
     * @return list<string>
     */
    public static function extractHiddenFields(Node\Stmt\Class_ $class, ?\Closure $resolve = null): array
    {
        return array_values(array_merge(
            self::extractFieldsFromProperty($class, 'hidden'),
            self::extractFieldsFromAttribute($class, 'Hidden', $resolve),
        ));
    }

    /**
     * Visible field names from a `$visible` property OR `#[Visible(...)]` attribute.
     *
     * A non-empty list is an allow-list: Eloquent serializes only the attributes it names.
     *
     * @param  (\Closure(Node\Name): string)|null  $resolve  The fully qualified name a reference resolves to
     * @return list<string>
     */
    public static function extractVisibleFields(Node\Stmt\Class_ $class, ?\Closure $resolve = null): array
    {
        return array_values(array_merge(
            self::extractFieldsFromProperty($class, 'visible'),
            self::extractFieldsFromAttribute($class, 'Visible', $resolve),
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
        return self::extractFieldsFromAttribute($class, 'Fillable', null, false);
    }

    /**
     * Field names declared by one of Eloquent's own attributes, such as `#[Fillable]` or
     * `#[Appends]`, on a class or trait.
     *
     * Unlike the short-name readers above, the attribute is matched on the fully qualified name
     * $resolve gives it, so an aliased import (`use ...\Fillable as F;`) is read and an attribute
     * of the same short name from another namespace is not. Model reads these attributes off a
     * trait as well as the class, which is why a trait is accepted.
     *
     * @param  \Closure(Node\Name): string  $resolve  The fully qualified name a reference resolves to
     * @return list<string>
     */
    public static function extractEloquentAttributeFields(Node\Stmt\ClassLike $class, string $attributeShortName, \Closure $resolve): array
    {
        return self::extractFieldsFromAttribute($class, $attributeShortName, $resolve, false);
    }

    /**
     * String field names from a class-level attribute, handling both the array
     * (`#[Attr(['a', 'b'])]`) and variadic (`#[Attr('a', 'b')]`) constructor shapes.
     *
     * Without $resolve the attribute is matched on its short name as written.
     *
     * With $asConstructed the arguments are read as Eloquent's attribute constructors keep
     * them: a leading array is the whole list and any argument after it is dropped, so
     * `#[Fillable(['a'], 'b')]` lists only `a`. Without it every argument is read, which is
     * what extractFillableFieldsFromAttribute() and extractEloquentAttributeFields() have
     * always returned to their callers.
     *
     * @param  (\Closure(Node\Name): string)|null  $resolve
     * @return list<string>
     */
    private static function extractFieldsFromAttribute(Node\Stmt\ClassLike $class, string $attributeShortName, ?\Closure $resolve = null, bool $asConstructed = true): array
    {
        $fields = [];

        foreach (self::attributes($class) as $attr) {
            if (! self::attributeIs($attr, $attributeShortName, $resolve)) {
                continue;
            }

            $args = $attr->args;
            if ($asConstructed && $args !== [] && $args[0]->value instanceof Node\Expr\Array_) {
                $args = [$args[0]];
            }

            foreach ($args as $arg) {
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
     * True if the class carries any class-level attribute that is one of $names.
     *
     * @param  list<string>  $names  Short names of Eloquent's own attributes
     * @param  (\Closure(Node\Name): string)|null  $resolve
     */
    private static function hasAttribute(Node\Stmt\Class_ $class, array $names, ?\Closure $resolve = null): bool
    {
        foreach (self::attributes($class) as $attr) {
            foreach ($names as $name) {
                if (self::attributeIs($attr, $name, $resolve)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * True if $attr is the Eloquent attribute $shortName: on its short name as written without
     * $resolve, on its resolved fully qualified name with it, ignoring case as PHP does.
     *
     * @param  (\Closure(Node\Name): string)|null  $resolve
     */
    private static function attributeIs(Node\Attribute $attr, string $shortName, ?\Closure $resolve): bool
    {
        return $resolve === null
            ? self::shortName($attr->name->toString()) === $shortName
            : strcasecmp($resolve($attr->name), self::ATTRIBUTE_NAMESPACE.'\\'.$shortName) === 0;
    }

    /**
     * All class-level attributes on the class or trait.
     *
     * @return list<Node\Attribute>
     */
    private static function attributes(Node\Stmt\ClassLike $class): array
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
