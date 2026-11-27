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
 *
 * A list entry may name a constant the class declares itself, through `self::`, `static::` or
 * the class's own name, and is read as that constant's value. Any other expression, such as
 * another class's constant or an enum case's `->value`, cannot be read here and is left out of
 * the field lists; the *ListsColumns() and hasUnreadableEntries() readers say where one was.
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

            if (! self::attributeIs($attr, 'Guarded', $resolve) || count($attr->args) !== 1) {
                continue;
            }

            $seen = [];
            $value = self::dereference($class, $attr->args[0]->value, $resolve, $seen);

            if ($value instanceof Node\Expr\Array_ && $value->items === []) {
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
            self::extractFieldsFromProperty($class, 'fillable', $resolve),
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
            self::extractFieldsFromProperty($class, 'guarded', $resolve),
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
            self::extractFieldsFromProperty($class, 'hidden', $resolve),
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
            self::extractFieldsFromProperty($class, 'visible', $resolve),
            self::extractFieldsFromAttribute($class, 'Visible', $resolve),
        ));
    }

    /**
     * What the class's own `$fillable` property says: null when the class does not declare
     * it, true when it lists a column or holds an entry that cannot be read here (assumed to
     * list one), false when it provably lists none.
     *
     * @param  (\Closure(Node\Name): string)|null  $resolve  The fully qualified name a reference resolves to
     */
    public static function fillablePropertyListsColumns(Node\Stmt\Class_ $class, ?\Closure $resolve = null): ?bool
    {
        $list = self::readProperty($class, 'fillable', $resolve);

        return $list === null ? null : ($list['fields'] !== [] || ! $list['complete']);
    }

    /**
     * What the class's own `#[Fillable]` attribute says, read as its constructor keeps the
     * arguments: null when the class carries none, true when it lists a column or holds an
     * entry that cannot be read here (assumed to list one), false when it provably lists none.
     *
     * @param  (\Closure(Node\Name): string)|null  $resolve  The fully qualified name a reference resolves to
     */
    public static function fillableAttributeListsColumns(Node\Stmt\Class_ $class, ?\Closure $resolve = null): ?bool
    {
        $list = self::readAttribute($class, 'Fillable', $resolve, true);

        return $list === null ? null : ($list['fields'] !== [] || ! $list['complete']);
    }

    /**
     * What the class's own `$guarded` property says: null when the class does not declare
     * it, true when it guards a column (`*` included) or holds an entry that cannot be read
     * here (assumed to guard one), false when it provably guards none.
     *
     * @param  (\Closure(Node\Name): string)|null  $resolve  The fully qualified name a reference resolves to
     */
    public static function guardedPropertyListsColumns(Node\Stmt\Class_ $class, ?\Closure $resolve = null): ?bool
    {
        $list = self::readProperty($class, 'guarded', $resolve);

        return $list === null ? null : ($list['fields'] !== [] || ! $list['complete']);
    }

    /**
     * The string field names one expression written in the class lists as a whole: a string
     * literal, an array literal, or a constant the class declares itself holding either. An
     * entry that cannot be read here is left out. For one entry of an array literal, use
     * fieldsListedByItem().
     *
     * @param  (\Closure(Node\Name): string)|null  $resolve  The fully qualified name a reference resolves to
     * @return list<string>
     */
    public static function fieldsListedBy(Node\Stmt\ClassLike $class, Node\Expr $expr, ?\Closure $resolve = null): array
    {
        $fields = [];
        self::collectFields($class, $expr, $resolve, $fields);

        return $fields;
    }

    /**
     * The string field names one entry of an array literal written in the class contributes:
     * a `...` spread contributes the names of the list it unpacks, any other entry its value
     * when that is a string, read through the class's own constants. An entry holding a list
     * names no field, and one that cannot be read here is left out.
     *
     * @param  (\Closure(Node\Name): string)|null  $resolve  The fully qualified name a reference resolves to
     * @return list<string>
     */
    public static function fieldsListedByItem(Node\Stmt\ClassLike $class, Node\Expr\ArrayItem $item, ?\Closure $resolve = null): array
    {
        $fields = [];
        self::collectItemFields($class, $item, $resolve, $fields);

        return $fields;
    }

    /**
     * True if the class's `$name` property or its same-named attribute (`$visible` and
     * `#[Visible]`) holds an entry that cannot be read here, so the field list read for it
     * may be missing names.
     *
     * @param  (\Closure(Node\Name): string)|null  $resolve  The fully qualified name a reference resolves to
     */
    public static function hasUnreadableEntries(Node\Stmt\Class_ $class, string $name, ?\Closure $resolve = null): bool
    {
        foreach ([self::readProperty($class, $name, $resolve), self::readAttribute($class, ucfirst($name), $resolve, true)] as $list) {
            if ($list !== null && ! $list['complete']) {
                return true;
            }
        }

        return false;
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
     * @param  bool  $asConstructed  Read the arguments as Eloquent's constructor keeps them, see extractFieldsFromAttribute()
     * @return list<string>
     */
    public static function extractEloquentAttributeFields(Node\Stmt\ClassLike $class, string $attributeShortName, \Closure $resolve, bool $asConstructed = false): array
    {
        return self::extractFieldsFromAttribute($class, $attributeShortName, $resolve, $asConstructed);
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
        return self::readAttribute($class, $attributeShortName, $resolve, $asConstructed)['fields'] ?? [];
    }

    /**
     * String field names from a `protected $name = [...]` array property.
     *
     * @param  (\Closure(Node\Name): string)|null  $resolve
     * @return list<string>
     */
    private static function extractFieldsFromProperty(Node\Stmt\Class_ $class, string $name, ?\Closure $resolve = null): array
    {
        return self::readProperty($class, $name, $resolve)['fields'] ?? [];
    }

    /**
     * The fields every same-named class-level attribute lists, and whether each entry could be
     * read. Null when the class carries no such attribute.
     *
     * @param  (\Closure(Node\Name): string)|null  $resolve
     * @return array{fields: list<string>, complete: bool}|null
     */
    private static function readAttribute(Node\Stmt\ClassLike $class, string $attributeShortName, ?\Closure $resolve, bool $asConstructed): ?array
    {
        $list = null;

        foreach (self::attributes($class) as $attr) {
            if (! self::attributeIs($attr, $attributeShortName, $resolve)) {
                continue;
            }

            $list ??= ['fields' => [], 'complete' => true];
            $args = $attr->args;

            if ($asConstructed && $args !== []) {
                $seen = [];
                if (self::dereference($class, $args[0]->value, $resolve, $seen) instanceof Node\Expr\Array_) {
                    $args = [$args[0]];
                }
            }

            foreach ($args as $arg) {
                $list['complete'] = self::collectFields($class, $arg->value, $resolve, $list['fields']) && $list['complete'];
            }
        }

        return $list;
    }

    /**
     * The fields the class's own `$name` property lists, and whether each entry could be read.
     * Null when the class does not declare the property; a declaration without a default
     * lists nothing.
     *
     * @param  (\Closure(Node\Name): string)|null  $resolve
     * @return array{fields: list<string>, complete: bool}|null
     */
    private static function readProperty(Node\Stmt\Class_ $class, string $name, ?\Closure $resolve): ?array
    {
        $list = null;

        foreach ($class->getProperties() as $property) {
            foreach ($property->props as $prop) {
                if ($prop->name->toString() !== $name) {
                    continue;
                }

                $list ??= ['fields' => [], 'complete' => true];

                if ($prop->default !== null) {
                    $list['complete'] = self::collectFields($class, $prop->default, $resolve, $list['fields']) && $list['complete'];
                }
            }
        }

        return $list;
    }

    /**
     * Append the string field names $expr lists to $fields: a string literal, an array literal
     * of entries, or a constant the class declares itself holding either, nested to any depth.
     * Returns false when some entry is anything else, so its names are unknown.
     *
     * @param  (\Closure(Node\Name): string)|null  $resolve
     * @param  list<string>  $fields
     * @param  list<string>  $seen  Constants being followed on the way here, so a cycle stops
     */
    private static function collectFields(Node\Stmt\ClassLike $class, Node\Expr $expr, ?\Closure $resolve, array &$fields, array $seen = []): bool
    {
        $expr = self::dereference($class, $expr, $resolve, $seen);

        if ($expr instanceof Node\Scalar\String_) {
            $fields[] = $expr->value;

            return true;
        }

        if (! $expr instanceof Node\Expr\Array_) {
            return false;
        }

        $complete = true;

        foreach ($expr->items as $item) {
            $complete = self::collectItemFields($class, $item, $resolve, $fields, $seen) && $complete;
        }

        return $complete;
    }

    /**
     * Append the field names one array entry contributes to $fields. A `...` spread
     * contributes the names of the list it unpacks; any other entry is one value, a name when
     * it is a string. An entry holding a list contributes nothing, because Eloquent compares
     * each key against the entries themselves and no key equals an array. Returns false when
     * the entry cannot be read.
     *
     * @param  (\Closure(Node\Name): string)|null  $resolve
     * @param  list<string>  $fields
     * @param  list<string>  $seen
     */
    private static function collectItemFields(Node\Stmt\ClassLike $class, Node\Expr\ArrayItem $item, ?\Closure $resolve, array &$fields, array $seen = []): bool
    {
        if ($item->unpack) {
            return self::collectFields($class, $item->value, $resolve, $fields, $seen);
        }

        $value = self::dereference($class, $item->value, $resolve, $seen);

        if ($value instanceof Node\Scalar\String_) {
            $fields[] = $value->value;

            return true;
        }

        return $value instanceof Node\Expr\Array_;
    }

    /**
     * Follow $expr through the constants the class declares itself to the expression one
     * finally holds. Null when it names a constant that cannot be followed: one of another
     * class, one the class does not declare (inherited, or from an interface or trait), or one
     * already in $seen.
     *
     * @param  (\Closure(Node\Name): string)|null  $resolve
     * @param  list<string>  $seen
     */
    private static function dereference(Node\Stmt\ClassLike $class, Node\Expr $expr, ?\Closure $resolve, array &$seen): ?Node\Expr
    {
        while ($expr instanceof Node\Expr\ClassConstFetch) {
            if (! $expr->class instanceof Node\Name
                || ! $expr->name instanceof Node\Identifier
                || ! self::namesOwnClass($class, $expr->class, $resolve)) {
                return null;
            }

            $name = $expr->name->toString();
            $value = self::ownConstantValue($class, $name);

            if ($value === null || in_array($name, $seen, true)) {
                return null;
            }

            $seen[] = $name;
            $expr = $value;
        }

        return $expr;
    }

    /**
     * True if $name refers to $class itself: `self`, `static`, or the class's own name.
     *
     * Without $resolve the own name must be written unqualified. With it, the reference and the
     * class's short name are both resolved as references in the declaring file: PHP refuses a
     * class whose name an import already holds, so the short name resolves to the class's own
     * fully qualified name.
     *
     * @param  (\Closure(Node\Name): string)|null  $resolve
     */
    private static function namesOwnClass(Node\Stmt\ClassLike $class, Node\Name $name, ?\Closure $resolve): bool
    {
        if ($name->isSpecialClassName()) {
            return in_array($name->toLowerString(), ['self', 'static'], true);
        }

        if ($class->name === null) {
            return false;
        }

        if ($resolve === null) {
            return $name->isUnqualified() && strcasecmp($name->toString(), $class->name->toString()) === 0;
        }

        return strcasecmp($resolve($name), $resolve(new Node\Name($class->name->toString()))) === 0;
    }

    /**
     * The value of a constant the class declares in its own body, null when it declares none
     * of that name. Constant names are case-sensitive.
     */
    private static function ownConstantValue(Node\Stmt\ClassLike $class, string $name): ?Node\Expr
    {
        foreach ($class->getConstants() as $classConst) {
            foreach ($classConst->consts as $const) {
                if ($const->name->toString() === $name) {
                    return $const->value;
                }
            }
        }

        return null;
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
    public static function attributeIs(Node\Attribute $attr, string $shortName, ?\Closure $resolve): bool
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
