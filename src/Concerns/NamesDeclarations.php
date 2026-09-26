<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use PhpParser\Node;

/**
 * One spelling of the subject a declaration is reported under.
 *
 * A named class, trait, interface or enum reports under its own name. An anonymous class
 * has none, and the two ways of coping with that are both bad on their own: withholding
 * the finding hides a real defect, and reporting "Unknown" names nothing the reader can
 * open. So it reports under the thing that identifies it, in the order PHP itself uses
 * when it builds a runtime name, which is what a stack trace will show for the same
 * declaration.
 *
 * Shared because several analyzers answer this question, and the answers had drifted:
 * one withheld the finding, one said "Unknown" and one said "Anonymous" for the very
 * same construct.
 */
trait NamesDeclarations
{
    /**
     * The subject to report this declaration under.
     *
     * @param  string|null  $enclosing  Name of the declaration this one sits inside, if any
     */
    private function declarationName(Node\Stmt\ClassLike $node, ?string $enclosing = null): string
    {
        if ($node->name !== null) {
            return $node->name->toString();
        }

        // PHP names an anonymous class after its parent, or failing that the first
        // interface it implements: new class extends Migration {} is Migration@anonymous.
        // Only a class can be anonymous, so nothing else needs asking.
        $inherited = $node instanceof Node\Stmt\Class_
            ? ($node->extends ?? ($node->implements[0] ?? null))
            : null;

        if ($inherited !== null) {
            return $inherited->toString().'@anonymous';
        }

        // Nothing inherited to borrow from, so fall back to the declaration it sits in.
        // A bare anonymous class at file level keeps PHP's own spelling, class@anonymous.
        return ($enclosing ?? 'class').'@anonymous';
    }
}
